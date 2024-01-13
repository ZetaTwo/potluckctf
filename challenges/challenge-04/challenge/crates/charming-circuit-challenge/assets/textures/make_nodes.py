from PIL import Image


def draw(x, w, color):
    for y in range(HEIGHT):
        for x_ in range(x, x+w):
            fake_image[(x_, y)] = tuple(color)

def lerp(xs, ys, l):
    return [x * (1 - l) + y * l for (x, y) in zip(xs, ys)]


DECAY = 0.2 ** (1 / 1024)
PRE_ACTIVE_COLOR = [3.0, 0.0, 0.0, 1.0]
ACTIVE_COLOR = [15.0, 0.0, 0.0, 1.0]
POST_ACTIVE_COLOR1 = [10.5, 0.0, 0.0, 1.0]
POST_ACTIVE_COLOR2 = [0.0, 1.5, 7.5, 1.0]
INACTIVE_COLOR = [0.0, 0.0, 0.0, 1.0]
HEIGHT = 1


def active():
    draw(0, 100, PRE_ACTIVE_COLOR)
    for i in range(100):
        draw(100 + i, 1, lerp(PRE_ACTIVE_COLOR, ACTIVE_COLOR, i/100))
    for i in range(50):
        draw(200 + i, 1, lerp(ACTIVE_COLOR, POST_ACTIVE_COLOR1, i/50))
    for i in range(50):
        draw(250 + i, 1, lerp(POST_ACTIVE_COLOR1, POST_ACTIVE_COLOR2, i/50))
    for i in range(724):
        draw(300 + i, 1, lerp(POST_ACTIVE_COLOR2,
             INACTIVE_COLOR, 1 - DECAY ** i))


def inactive1():
    for i in range(1024):
        draw(i, 1, lerp(POST_ACTIVE_COLOR2,
             INACTIVE_COLOR, 1 - DECAY ** (i + 724)))


def inactive2():
    for i in range(1024):
        draw(i, 1, lerp(POST_ACTIVE_COLOR2,
             INACTIVE_COLOR, 1 - DECAY ** (i + 1024 + 724)))


def inactive3():
    for i in range(1024):
        draw(i, 1, lerp(POST_ACTIVE_COLOR2,
             INACTIVE_COLOR, 1 - DECAY ** (i + 2048 + 724)))


def inactive4():
    final_color = lerp(POST_ACTIVE_COLOR2,
                       INACTIVE_COLOR, 1 - DECAY ** (3072 + 724))
    draw(0, 1024, final_color)


def active_next2():
    for i in range(800):
        draw(i, 1, lerp(POST_ACTIVE_COLOR2,
             INACTIVE_COLOR, 1 - DECAY ** (i + 1024 + 724)))
    final_color = lerp(POST_ACTIVE_COLOR2, INACTIVE_COLOR,
                       1 - DECAY ** (800 + 1024 + 724))
    for i in range(224):
        draw(800 + i, 1, lerp(final_color, PRE_ACTIVE_COLOR, i / 224))


def active_next3():
    for i in range(800):
        draw(i, 1, lerp(POST_ACTIVE_COLOR2,
             INACTIVE_COLOR, 1 - DECAY ** (i + 2048 + 724)))
    final_color = lerp(POST_ACTIVE_COLOR2, INACTIVE_COLOR,
                       1 - DECAY ** (800 + 2048 + 724))
    for i in range(224):
        draw(800 + i, 1, lerp(final_color, PRE_ACTIVE_COLOR, i / 224))


def active_next4():
    final_color = lerp(POST_ACTIVE_COLOR2,
                       INACTIVE_COLOR, 1 - DECAY ** (3072 + 724))
    draw(0, 800, final_color)
    for i in range(224):
        draw(800 + i, 1, lerp(final_color, PRE_ACTIVE_COLOR, i / 224))

def make_and_save(f, name):
    global im, fake_image
    fake_image = {}
    im = Image.new("RGBA", (1024, HEIGHT))
    f()
    max_colors = [max(c[i] for c in fake_image.values()) for i in range(4)]
    div_max_colors = [(m if m != 0 else 1) for m in max_colors]
    for ((x, y), color) in fake_image.items():
        im.putpixel((x, y), tuple([int(c / m * 255) for (m, c) in zip(div_max_colors, color)]))
    im.save(name)
    print(name, max_colors)


make_and_save(active, "node_active.png")
make_and_save(inactive1, "node_inactive1.png")
make_and_save(inactive2, "node_inactive2.png")
make_and_save(inactive3, "node_inactive3.png")
make_and_save(inactive4, "node_inactive4.png")
make_and_save(active_next2, "node_active_next2.png")
make_and_save(active_next3, "node_active_next3.png")
make_and_save(active_next4, "node_active_next4.png")
