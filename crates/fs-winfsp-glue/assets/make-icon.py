"""Generate a 32x32 RGBA app icon for XFS Mount (raw bytes for CreateDIBSection)."""
import os, math

SIZE = 32
OUT = os.path.join(os.path.dirname(__file__), "icon-32.rgba")

BG = (0x1E, 0x24, 0x31)       # dark slate
BORDER = (0x3C, 0x47, 0x5C)   # lighter edge
ACCENT = (0xFF, 0xB1, 0x3D)   # amber
GLYPH_SHADOW = (0x8A, 0x5A, 0x14)

def in_rounded_rect(x, y, x0, y0, x1, y1, r):
    if x < x0 or x > x1 or y < y0 or y > y1:
        return False
    cx = min(max(x, x0 + r), x1 - r)
    cy = min(max(y, y0 + r), y1 - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r

def seg_dist(px, py, ax, ay, bx, by):
    vx, vy = bx - ax, by - ay
    wx, wy = px - ax, py - ay
    t = (wx * vx + wy * vy) / float(vx * vx + vy * vy)
    t = max(0.0, min(1.0, t))
    dx, dy = px - (ax + t * vx), py - (ay + t * vy)
    return math.hypot(dx, dy)

px = bytearray()
for y in range(SIZE):
    for x in range(SIZE):
        fx, fy = x + 0.5, y + 0.5
        if not in_rounded_rect(fx, fy, 0.5, 0.5, SIZE - 1.5, SIZE - 1.5, 7.0):
            px += bytes((0, 0, 0, 0))
            continue
        edge = not in_rounded_rect(fx, fy, 1.5, 1.5, SIZE - 2.5, SIZE - 2.5, 6.2)
        r, g, b = BORDER if edge else BG
        # subtle vertical gradient
        if not edge:
            k = 1.0 - (y / SIZE) * 0.18
            r, g, b = int(r * k), int(g * k), int(b * k)

        d1 = seg_dist(fx, fy, 10.0, 10.0, 22.0, 22.0)
        d2 = seg_dist(fx, fy, 22.0, 10.0, 10.0, 22.0)
        d = min(d1, d2)
        if d <= 1.9:
            r, g, b = ACCENT
        elif d <= 2.6:
            r, g, b = GLYPH_SHADOW
        px += bytes((r, g, b, 255))

with open(OUT, "wb") as f:
    f.write(px)
print("wrote", OUT, len(px), "bytes")
