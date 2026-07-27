package com.anvil.passkeyeditor.ui.settings;

import java.awt.Component;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.Path2D;
import java.awt.geom.Point2D;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.Icon;

/**
 * The GitHub mark, drawn as a scalable {@link Icon} rather than shipped as an image: it is filled with
 * the host component's foreground, so it stays legible in a light or a dark Burp theme and follows the
 * font scale. Outline data is the standard 24x24 mark path, parsed once into a {@link Path2D}.
 *
 * Parsing is deliberately forgiving: if the outline cannot be built the icon draws nothing, so a
 * bad path can never break the panel that hosts it.
 */
final class GithubMark implements Icon {

    /** Source viewBox edge of {@link #OUTLINE}; the icon scales from this to its requested size. */
    private static final double SRC = 24d;

    private static final String PATH =
            "M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 "
            + "0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 "
            + "3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 "
            + "1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-"
            + "5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 "
            + "1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-"
            + "1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-"
            + "5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C"
            + "20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12";

    /** Commands, and numbers that may run together ({@code .6.113}, {@code 12-.015}). */
    private static final Pattern TOKEN = Pattern.compile(
            "([MmLlHhVvCcZz])|(-?(?:\\d+\\.?\\d*|\\.\\d+)(?:[eE][+-]?\\d+)?)");

    /** Declared after {@link #TOKEN}: static initializers run in order, and the parse needs it. */
    private static final Path2D OUTLINE = outline();

    private final int size;

    GithubMark(int size) {
        this.size = size;
    }

    @Override
    public int getIconWidth() {
        return size;
    }

    @Override
    public int getIconHeight() {
        return size;
    }

    @Override
    public void paintIcon(Component c, Graphics g, int x, int y) {
        if (OUTLINE == null) {
            return;
        }
        Graphics2D g2 = (Graphics2D) g.create();
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.translate(x, y);
            g2.scale(size / SRC, size / SRC);
            g2.setColor(c.getForeground());
            g2.fill(OUTLINE);
        } finally {
            g2.dispose();
        }
    }

    private static Path2D outline() {
        try {
            return parse(PATH);
        } catch (RuntimeException e) {
            return null; // Draw nothing rather than break the hosting panel.
        }
    }

    /**
     * Parse the subset of SVG path syntax this outline uses: move, line, horizontal/vertical line,
     * cubic curve and close, absolute or relative, with implicit repetition of the last command.
     */
    private static Path2D parse(String d) {
        List<String> tokens = new ArrayList<>();
        Matcher m = TOKEN.matcher(d);
        while (m.find()) {
            tokens.add(m.group());
        }

        Path2D.Double path = new Path2D.Double();
        Point2D.Double cur = new Point2D.Double();
        Point2D.Double start = new Point2D.Double();
        char cmd = 0;
        int i = 0;
        while (i < tokens.size()) {
            String t = tokens.get(i);
            if (Character.isLetter(t.charAt(0))) {
                cmd = t.charAt(0);
                i++;
                if (cmd == 'Z' || cmd == 'z') {
                    path.closePath();
                    cur.setLocation(start);
                }
                continue;
            }
            boolean rel = Character.isLowerCase(cmd);
            double ox = rel ? cur.x : 0;
            double oy = rel ? cur.y : 0;
            switch (Character.toUpperCase(cmd)) {
                case 'M' -> {
                    cur.setLocation(ox + num(tokens, i), oy + num(tokens, i + 1));
                    i += 2;
                    path.moveTo(cur.x, cur.y);
                    start.setLocation(cur);
                    cmd = rel ? 'l' : 'L'; // Extra pairs after a moveto are lines.
                }
                case 'L' -> {
                    cur.setLocation(ox + num(tokens, i), oy + num(tokens, i + 1));
                    i += 2;
                    path.lineTo(cur.x, cur.y);
                }
                case 'H' -> {
                    cur.x = ox + num(tokens, i);
                    i += 1;
                    path.lineTo(cur.x, cur.y);
                }
                case 'V' -> {
                    cur.y = oy + num(tokens, i);
                    i += 1;
                    path.lineTo(cur.x, cur.y);
                }
                case 'C' -> {
                    double x1 = ox + num(tokens, i);
                    double y1 = oy + num(tokens, i + 1);
                    double x2 = ox + num(tokens, i + 2);
                    double y2 = oy + num(tokens, i + 3);
                    cur.setLocation(ox + num(tokens, i + 4), oy + num(tokens, i + 5));
                    i += 6;
                    path.curveTo(x1, y1, x2, y2, cur.x, cur.y);
                }
                default -> throw new IllegalArgumentException("unsupported command: " + cmd);
            }
        }
        return path;
    }

    private static double num(List<String> tokens, int i) {
        return Double.parseDouble(tokens.get(i));
    }
}
