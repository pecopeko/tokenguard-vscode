"""Generate the 128x128 Marketplace icon for TokenGuard using Python Pillow."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw


def generate_icon(output_path: Path) -> None:
    """Render a crisp 4x supersampled 128x128 TokenGuard shield + token gauge icon."""
    size = 512  # Render at 4x and downsample with LANCZOS for crisp anti-aliasing
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Rounded dark slate background (#0F172A) with subtle emerald rim (#1E293B)
    pad = 16
    radius = 96
    draw.rounded_rectangle(
        [pad, pad, size - pad, size - pad],
        radius=radius,
        fill=(15, 23, 42, 255),
        outline=(30, 58, 76, 255),
        width=10,
    )

    # Subtle alpha-composited radial emerald highlight at top center
    glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    gdraw = ImageDraw.Draw(glow)
    for step, r in enumerate([210, 175, 140, 105]):
        alpha = 14 + step * 6
        gdraw.ellipse(
            [256 - r, 110 - int(r * 0.65), 256 + r, 110 + int(r * 0.85)],
            fill=(16, 185, 129, alpha),
        )
    # Mask glow to rounded container
    mask = Image.new("L", (size, size), 0)
    mdraw = ImageDraw.Draw(mask)
    mdraw.rounded_rectangle([pad + 5, pad + 5, size - pad - 5, size - pad - 5], radius=radius - 4, fill=255)
    glow_clipped = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    glow_clipped.paste(glow, (0, 0), mask)
    img = Image.alpha_composite(img, glow_clipped)
    draw = ImageDraw.Draw(img)

    # Outer emerald shield silhouette
    shield_outer = [
        (256, 68),   # top apex
        (410, 128),  # top right
        (396, 278),  # mid right
        (346, 372),  # lower right
        (256, 444),  # bottom tip
        (166, 372),  # lower left
        (116, 278),  # mid left
        (102, 128),  # top left
    ]
    draw.polygon(shield_outer, fill=(16, 185, 129, 255))

    # Inner dark shield core
    shield_inner = [
        (256, 94),
        (386, 144),
        (374, 274),
        (330, 356),
        (256, 416),
        (182, 356),
        (138, 274),
        (126, 144),
    ]
    draw.polygon(shield_inner, fill=(13, 21, 38, 255))

    # Subtle left-half bevel shading inside shield
    shield_left_tint = [
        (256, 94),
        (256, 416),
        (182, 356),
        (138, 274),
        (126, 144),
    ]
    draw.polygon(shield_left_tint, fill=(21, 35, 58, 255))

    # Three ascending token/cost meter bars inside shield (sky / emerald / amber)
    bar_bottom = 330
    bar_width = 36
    bars = [
        (178, 260, (56, 189, 248, 255)),   # sky-400
        (238, 212, (52, 211, 153, 255)),   # emerald-400
        (298, 166, (250, 204, 21, 255)),   # yellow-400
    ]
    for x0, y0, color in bars:
        draw.rounded_rectangle(
            [x0, y0, x0 + bar_width, bar_bottom],
            radius=10,
            fill=color,
        )

    # Redaction baseline bar beneath meter
    draw.rounded_rectangle(
        [178, 348, 334, 366],
        radius=9,
        fill=(148, 163, 184, 255),
    )

    # Glowing emerald shield apex node
    draw.ellipse([239, 114, 273, 148], fill=(16, 185, 129, 255))
    draw.ellipse([248, 123, 264, 139], fill=(236, 253, 245, 255))

    final_img = img.resize((128, 128), Image.Resampling.LANCZOS)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    final_img.save(output_path, format="PNG", optimize=True)


if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "assets" / "icon.png"
    generate_icon(out)
    print(f"Generated {out} ({out.stat().st_size} bytes)")
