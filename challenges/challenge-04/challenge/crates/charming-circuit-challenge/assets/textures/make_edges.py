from PIL import Image
import math


def draw_gaussian(x, spread, center, color, amplitude=1):
    for y in range(HEIGHT):
        cur_color = lerp([0, 0, 0], color,
                         amplitude * math.exp(-(y - center) ** 2 / spread**2))
        im.putpixel((x, y), tuple([int(c * 255) for c in cur_color]))


def draw_double_gaussian(x, spread, center1, center2, color, amplitude=1):
    for y in range(HEIGHT):
        cur_color = lerp([0, 0, 0], color,
                         min(amplitude * (math.exp(-(y - center1) ** 2 / spread**2) +
                                          math.exp(-(y - center2) ** 2 / spread**2)), 1))
        im.putpixel((x, y), tuple([int(c * 255) for c in cur_color]))


def lerp(xs, ys, l):
    return [x * (1 - l) + y * l for (x, y) in zip(xs, ys)]


DECAY = 0.2 ** (1 / 1024)
PRE_ACTIVE_COLOR = [0.2, 0.0, 0.0, 1.0]
ACTIVE_COLOR = [1.0, 0.0, 0.0, 1.0]
POST_ACTIVE_COLOR1 = [0.7, 0.0, 0.0, 1.0]
POST_ACTIVE_COLOR2 = [0.0, 0.1, 0.5, 1.0]
INACTIVE_COLOR = [0.0, 0.0, 0.0, 1.0]
HEIGHT = 1024
SPREAD = 100


def inactive():
    pass


def active1():
    pos = 150
    center = -200
    for _ in range(700):
        draw_gaussian(pos, SPREAD, center, ACTIVE_COLOR)
        pos += 1
        center += (1024 + 400) / 700


def active2():
    pos = 150
    center = 1024 + 200
    for _ in range(750):
        draw_gaussian(pos, SPREAD, center, ACTIVE_COLOR)
        pos += 1
        center -= (1024 + 400) / 750


def overactive1():
    pos = 150
    center = -200
    for _ in range(200):
        draw_gaussian(pos, SPREAD, center, ACTIVE_COLOR)
        pos += 1
        center += (1024 + 400) / 750
    for i in range(400):
        draw_gaussian(pos, SPREAD * (1 + i / 500), center,
                      ACTIVE_COLOR, amplitude=(400 - i) / 400)
        pos += 1
        if i < 150:
            center += (1024 + 400) / 750
        elif 150 <= i < 350:
            center += (1024 + 400) / 750 * ((350 - i) / 200)


def overactive2():
    pos = 150
    center = 1024 + 200
    for _ in range(325):
        draw_gaussian(pos, SPREAD, center, ACTIVE_COLOR)
        pos += 1
        center -= (1024 + 400) / 750
    for i in range(400):
        draw_gaussian(pos, SPREAD * (1 + i / 500), center,
                      ACTIVE_COLOR, amplitude=(400 - i) / 400)
        pos += 1
        if i < 150:
            center -= (1024 + 400) / 750
        elif 150 <= i < 350:
            center -= (1024 + 400) / 750 * ((350 - i) / 200)


def double_active():
    pos = 150
    center1 = - 200
    center2 = 1024 + 200
    for _ in range(200):
        draw_double_gaussian(pos, SPREAD, center1, center2, ACTIVE_COLOR)
        pos += 1
        center1 += (1024 + 400) / 750
        center2 -= (1024 + 400) / 750
    for i in range(400):
        draw_double_gaussian(pos, SPREAD, center1, center2,
                             ACTIVE_COLOR, amplitude=(400 - i) / 400)
        pos += 1
        if i < 175:
            center1 += (1024 + 400) / 750
            center2 -= (1024 + 400) / 750


def make_and_save(f, name):
    global im
    im = Image.new("RGBA", (1024, HEIGHT))
    f()
    im.save(name)


# make_and_save(inactive, "edge_inactive.png")
# make_and_save(active1, "edge_active1.png")
# make_and_save(active2, "edge_active2.png")
make_and_save(overactive1, "edge_overactive1.png")
make_and_save(overactive2, "edge_overactive2.png")
# make_and_save(double_active, "edge_double_active.png")
