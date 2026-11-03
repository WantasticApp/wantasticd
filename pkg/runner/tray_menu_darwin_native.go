//go:build darwin && !nosystray

package runner

// The Objective-C half of tray_menu_darwin.go. It lives apart because a cgo
// file with //export may only declare C functions, not define them.

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

extern void wantasticMenuOpened(int menuId);
extern void wantasticMenuClosed(int menuId);

// Rows with a view do not get AppKit's own drawing, so these follow the
// system menu: selection inset and corner radius, title column, row height.
static const CGFloat wtRowHeight  = 24;
static const CGFloat wtSelInset   = 5;
static const CGFloat wtSelRadius  = 4;
static const CGFloat wtStateX     = 13;
static const CGFloat wtTitleX     = 30.5;
static const CGFloat wtTitleRight = 14;
static const CGFloat wtSwitchW    = 26;
static const CGFloat wtSwitchH    = 15;

// WTKeepOpenView stands in for a menu item's own drawing so a click runs
// the item's action and the menu stays open: an ordinary NSMenuItem always
// closes its menu. Title, state, enabled and tooltip come from the item.
@interface WTKeepOpenView : NSView
// image, when set, is drawn image-size above the title (a QR code): an
// NSMenuItem image would push every title in the menu to the right of it.
@property (nonatomic, strong) NSImage *image;
// isSwitch draws the item's on/off state as a switch at the right edge
// instead of a checkmark.
@property (nonatomic) BOOL isSwitch;
@property (nonatomic, copy) NSString *drawn;
@end

@implementation WTKeepOpenView

- (instancetype)init {
	self = [super initWithFrame:NSMakeRect(0, 0, 120, wtRowHeight)];
	self.autoresizingMask = NSViewWidthSizable;
	return self;
}

- (BOOL)acceptsFirstMouse:(NSEvent *)event { return YES; }

// The menu decides which row is highlighted (isHighlighted): own hover
// tracking misses the exit when the pointer passes quickly and leaves a
// row stuck blue.
- (void)mouseDown:(NSEvent *)event {}

- (void)mouseUp:(NSEvent *)event {
	NSMenuItem *item = self.enclosingMenuItem;
	if (item == nil || !item.isEnabled || item.action == nil) return;
	[NSApp sendAction:item.action to:item.target from:item];
}

- (NSFont *)titleFont {
	NSFont *f = self.enclosingMenuItem.menu.font;
	return f ?: [NSFont menuFontOfSize:0];
}

// sync redraws when the item changed since the last draw.
- (void)sync {
	NSMenuItem *item = self.enclosingMenuItem;
	if (item == nil) return;
	NSString *key = [NSString stringWithFormat:@"%@|%d|%ld|%d|%p", item.title, item.isEnabled, (long)item.state, item.isHighlighted, self.image];
	if (![key isEqualToString:self.drawn]) {
		self.drawn = key;
		self.toolTip = item.toolTip;
		CGFloat w = ceil([item.title sizeWithAttributes:@{NSFontAttributeName: [self titleFont]}].width) + wtTitleX + wtTitleRight;
		if (self.isSwitch) w += wtSwitchW + 12;
		CGFloat h = wtRowHeight;
		if (self.image != nil) {
			h += self.image.size.height + 8;
			w = MAX(w, self.image.size.width + wtTitleX + wtTitleRight);
		}
		if (w > NSWidth(self.frame) || h != NSHeight(self.frame)) [self setFrameSize:NSMakeSize(MAX(w, NSWidth(self.frame)), h)];
		[self setNeedsDisplay:YES];
	}
}

- (void)drawRect:(NSRect)dirty {
	NSMenuItem *item = self.enclosingMenuItem;
	if (item == nil) return;
	BOOL enabled = item.isEnabled;
	BOOL selected = enabled && item.isHighlighted;
	if (selected) {
		[[NSColor controlAccentColor] setFill];
		[[NSBezierPath bezierPathWithRoundedRect:NSInsetRect(self.bounds, wtSelInset, 0) xRadius:wtSelRadius yRadius:wtSelRadius] fill];
	}
	NSColor *color = !enabled ? [NSColor disabledControlTextColor] : selected ? [NSColor selectedMenuItemTextColor] : [NSColor labelColor];
	NSMutableParagraphStyle *para = [[NSMutableParagraphStyle alloc] init];
	para.lineBreakMode = NSLineBreakByTruncatingTail;
	NSDictionary *attrs = @{NSFontAttributeName: [self titleFont], NSForegroundColorAttributeName: color, NSParagraphStyleAttributeName: para};
	CGFloat h = [@"Ag" sizeWithAttributes:attrs].height;
	// The title sits in the bottom row; an image fills the space above it.
	CGFloat y = floor((wtRowHeight - h) / 2);
	if (self.image != nil) {
		NSSize sz = self.image.size;
		[self.image drawInRect:NSMakeRect(wtTitleX, wtRowHeight, sz.width, sz.height)];
	}
	CGFloat right = wtTitleRight;
	if (self.isSwitch) {
		BOOL on = item.state == NSControlStateValueOn;
		NSRect track = NSMakeRect(NSWidth(self.bounds) - wtTitleRight - wtSwitchW, floor((wtRowHeight - wtSwitchH) / 2), wtSwitchW, wtSwitchH);
		NSColor *fill = on ? (selected ? [NSColor whiteColor] : [NSColor controlAccentColor]) : [[NSColor labelColor] colorWithAlphaComponent:0.18];
		if (!enabled) fill = [fill colorWithAlphaComponent:0.4];
		[fill setFill];
		[[NSBezierPath bezierPathWithRoundedRect:track xRadius:wtSwitchH / 2 yRadius:wtSwitchH / 2] fill];
		CGFloat knob = wtSwitchH - 3;
		NSRect k = NSMakeRect(on ? NSMaxX(track) - knob - 1.5 : NSMinX(track) + 1.5, NSMinY(track) + 1.5, knob, knob);
		[(on && selected ? [NSColor controlAccentColor] : [NSColor whiteColor]) setFill];
		[[NSBezierPath bezierPathWithOvalInRect:k] fill];
		right += wtSwitchW + 12;
	} else if (item.state == NSControlStateValueOn) {
		[@"✓" drawAtPoint:NSMakePoint(wtStateX, y) withAttributes:attrs];
	}
	[item.title drawInRect:NSMakeRect(wtTitleX, y, NSWidth(self.bounds) - wtTitleX - right, h) withAttributes:attrs];
}

@end

static NSMutableArray<WTKeepOpenView *> *wtViews;
static NSMutableArray *wtWatchers;
static NSTimer *wtTimer;
static int wtOpenMenus;

// WTMenuWatcher tells Go when a menu opens and closes, and keeps the
// keep-open rows in step with their items while any menu is showing.
@interface WTMenuWatcher : NSObject <NSMenuDelegate>
@property (nonatomic) int menuId;
@end

@implementation WTMenuWatcher

- (void)menuWillOpen:(NSMenu *)menu {
	if (wtOpenMenus++ == 0) {
		for (WTKeepOpenView *v in wtViews) [v sync];
		wtTimer = [NSTimer timerWithTimeInterval:0.15 repeats:YES block:^(NSTimer *t) {
			for (WTKeepOpenView *v in wtViews) [v sync];
		}];
		[[NSRunLoop mainRunLoop] addTimer:wtTimer forMode:NSRunLoopCommonModes];
	}
	wantasticMenuOpened(self.menuId);
}

- (void)menuDidClose:(NSMenu *)menu {
	if (wtOpenMenus > 0 && --wtOpenMenus == 0) {
		[wtTimer invalidate];
		wtTimer = nil;
	}
	wantasticMenuClosed(self.menuId);
}

@end

// wtRootMenu is the status item's menu, owned by the systray library's
// app delegate.
static NSMenu *wtRootMenu(void) {
	id delegate = [NSApp delegate];
	@try {
		id menu = [(NSObject *)delegate valueForKey:@"menu"];
		if ([menu isKindOfClass:[NSMenu class]]) return menu;
	} @catch (NSException *e) {
	}
	return nil;
}

static NSMenuItem *wtFind(NSMenu *menu, NSInteger tag) {
	NSMenuItem *item = [menu itemWithTag:tag];
	if (item != nil) return item;
	for (NSMenuItem *it in menu.itemArray) {
		if (it.hasSubmenu) {
			item = wtFind(it.submenu, tag);
			if (item != nil) return item;
		}
	}
	return nil;
}

static void wtInit(void) {
	if (wtViews == nil) {
		wtViews = [NSMutableArray array];
		wtWatchers = [NSMutableArray array];
	}
}

// wtWatchMenu reports opens of the root menu (menuId 0) or of the submenu
// under the item menuId.
void wtWatchMenu(int menuId) {
	dispatch_async(dispatch_get_main_queue(), ^{
		wtInit();
		NSMenu *root = wtRootMenu();
		NSMenu *menu = root;
		if (menuId != 0) {
			menu = root ? wtFind(root, menuId).submenu : nil;
		}
		if (menu == nil || menu.delegate != nil) return;
		WTMenuWatcher *w = [[WTMenuWatcher alloc] init];
		w.menuId = menuId;
		[wtWatchers addObject:w]; // NSMenu holds its delegate weakly
		menu.delegate = w;
	});
}

void wtKeepOpen(int menuId, int asSwitch) {
	dispatch_async(dispatch_get_main_queue(), ^{
		wtInit();
		NSMenu *root = wtRootMenu();
		NSMenuItem *item = root ? wtFind(root, menuId) : nil;
		if (item == nil || item.hasSubmenu) return;
		WTKeepOpenView *v = (WTKeepOpenView *)item.view;
		if (![v isKindOfClass:[WTKeepOpenView class]]) {
			v = [[WTKeepOpenView alloc] init];
			item.view = v;
			[wtViews addObject:v];
		}
		if (asSwitch) v.isSwitch = YES;
		v.drawn = nil;
		[v sync];
	});
}

// wtSetImage gives an item a picture drawn at points x points (the library
// shrinks every item image to 16).
void wtSetImage(int menuId, const void *bytes, int length, int points) {
	NSData *data = [NSData dataWithBytes:bytes length:length];
	dispatch_async(dispatch_get_main_queue(), ^{
		wtInit();
		NSMenu *root = wtRootMenu();
		NSMenuItem *item = root ? wtFind(root, menuId) : nil;
		NSImage *image = [[NSImage alloc] initWithData:data];
		if (item == nil || image == nil || item.hasSubmenu) return;
		[image setSize:NSMakeSize(points, points)];
		WTKeepOpenView *v = (WTKeepOpenView *)item.view;
		if (![v isKindOfClass:[WTKeepOpenView class]]) {
			v = [[WTKeepOpenView alloc] init];
			item.view = v;
			[wtViews addObject:v];
		}
		v.image = image;
		v.drawn = nil;
		[v sync];
	});
}
*/
import "C"
