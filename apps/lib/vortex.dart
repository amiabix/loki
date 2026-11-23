import 'dart:math' as math;
import 'dart:ui' as ui;

import 'package:flutter/scheduler.dart';
import 'package:flutter/widgets.dart';

class Vortex extends StatefulWidget {
  const Vortex({
    super.key,
    required this.dark,
    this.still = false,
    this.locked = false,
  });

  final bool dark;
  final bool still;
  final bool locked;

  @override
  State<Vortex> createState() => _VortexState();
}

class _VortexState extends State<Vortex> with SingleTickerProviderStateMixin {
  final _cycle = ValueNotifier<double>(0);
  late final Ticker _ticker = createTicker(_tick);
  bool _motionAllowed = false;

  bool get _animate => _motionAllowed && !widget.still && !widget.locked;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _motionAllowed =
        TickerMode.valuesOf(context).enabled &&
        !(MediaQuery.maybeReduceMotionOf(context) ?? false) &&
        !(MediaQuery.maybeDisableAnimationsOf(context) ?? false);
    _updateTicker();
  }

  @override
  void didUpdateWidget(covariant Vortex oldWidget) {
    super.didUpdateWidget(oldWidget);
    _updateTicker();
  }

  void _updateTicker() {
    if (_animate) {
      if (!_ticker.isActive) _ticker.start();
    } else {
      _ticker.stop();
      _cycle.value = 0;
    }
  }

  void _tick(Duration elapsed) {
    _cycle.value = (elapsed.inMilliseconds ~/ 50 % 500) / 500;
  }

  @override
  void dispose() {
    _ticker.dispose();
    _cycle.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => IgnorePointer(
    child: ExcludeSemantics(
      child: RepaintBoundary(
        child: SizedBox.expand(
          child: CustomPaint(
            painter: _VortexPainter(widget.dark, widget.locked, _cycle),
            isComplex: true,
            willChange: _animate,
          ),
        ),
      ),
    ),
  );
}

const _turn = 2 * math.pi;

double Function() _random(int seed) => () {
  seed = (seed * 16807) % 2147483647;
  return seed / 2147483647;
};

class _VortexDepth {
  _VortexDepth(this.t)
    : expansion = math.pow(t, 1.65).toDouble(),
      rise = -0.16 * (1 - math.exp(-11 * t)) + 0.31 * t * t;

  final double t;
  final double expansion;
  final double rise;
}

class _VortexPainter extends CustomPainter {
  _VortexPainter(this.dark, this.locked, this.cycle)
    : super(repaint: locked ? null : cycle);

  final bool dark;
  final bool locked;
  final ValueNotifier<double> cycle;

  Color get _mint => dark ? const Color(0xff2fd8a8) : const Color(0xff0e9f78);
  Color get _gold => dark ? const Color(0xffe8b44a) : const Color(0xffb7851f);

  static const _lip = 0.13;
  static final _lipDepth = _VortexDepth(_lip);
  static final _ringDepths = List.generate(38, (i) => _VortexDepth(i / 37));
  static final _ribDepths = List.generate(86, (i) => _VortexDepth(i / 85));

  @override
  void paint(Canvas canvas, Size size) {
    if (size.isEmpty) return;
    final bounds = Offset.zero & size;
    canvas.save();
    canvas.clipRect(bounds, doAntiAlias: false);
    canvas.drawRect(
      bounds,
      Paint()..color = dark ? const Color(0xff0a0c10) : const Color(0xfff6f7f9),
    );

    canvas.saveLayer(bounds, Paint());
    const black = Color(0xff000000);
    final ui.Shader mask;
    if (locked) {
      _paintTunnel(canvas, size);
      final opacity = black.withValues(alpha: 0.65);
      mask = ui.Gradient.radial(
        bounds.center,
        600,
        [opacity, opacity, const Color(0x00000000)],
        const [0, 140 / 600, 1],
      );
    } else {
      _paintVortex(canvas, size);
      mask = ui.Gradient.linear(
        Offset.zero,
        Offset(size.width, 0),
        [black.withValues(alpha: 0.40), black.withValues(alpha: 0.39), black],
        const [0, 0.43, 0.74],
      );
    }
    canvas.drawRect(
      bounds,
      Paint()
        ..shader = mask
        ..blendMode = BlendMode.dstIn,
    );
    canvas.restore();
    canvas.restore();
  }

  void _paintVortex(Canvas canvas, Size size) {
    final w = size.width, h = size.height;
    final eye = Offset(w * 0.816, h * 0.24);
    final mint = _mint, gold = _gold;
    final phase = cycle.value;
    final twist = 1.23 + 0.045 * math.sin(phase * _turn);

    final bloomRadius = w * 0.48;
    final start = math.min(4 / bloomRadius, 1.0);
    final bloom = mint.withValues(alpha: dark ? 0.21 : 0.17);
    canvas.save();
    canvas.translate(eye.dx, eye.dy);
    canvas.scale(1, 0.42);
    canvas.drawCircle(
      Offset.zero,
      bloomRadius,
      Paint()
        ..shader = ui.Gradient.radial(
          Offset.zero,
          bloomRadius,
          [
            bloom,
            bloom,
            mint.withValues(alpha: dark ? 0.10 : 0.09),
            mint.withValues(alpha: 0),
          ],
          [0, start, (1 + start) / 2, 1],
        ),
    );
    canvas.restore();

    Offset point(_VortexDepth depth, double angle) {
      final a = angle + twist * (1 - depth.t);
      final x = math.cos(a) * w * (0.024 + 1.08 * depth.expansion);
      final y = math.sin(a) * h * (0.014 + 0.97 * depth.expansion);
      return Offset(
        eye.dx - w * 0.28 * depth.expansion + x,
        eye.dy + h * depth.rise + y - 0.13 * x,
      );
    }

    final cx = eye.dx - w * 0.28 * _lipDepth.expansion;
    final cy = eye.dy + h * _lipDepth.rise;
    final rx = w * (0.024 + 1.08 * _lipDepth.expansion);
    final ry = h * (0.014 + 0.97 * _lipDepth.expansion);
    void trace(Path path, int steps, {_VortexDepth? ring, double? ribAngle}) {
      var drawing = false;
      for (var i = 0; i <= steps; i++) {
        final depth = ring ?? _ribDepths[i];
        final p = point(depth, ribAngle ?? i / steps * _turn);
        final dx = (p.dx - cx) / rx;
        final dy = (p.dy - cy + (p.dx - cx) * 0.13) / ry;
        if (depth.t >= _lip ||
            dx * dx + dy * dy <= 1 ||
            (dy < 0 && dx.abs() < 1)) {
          if (drawing) {
            path.lineTo(p.dx, p.dy);
          } else {
            path.moveTo(p.dx, p.dy);
          }
          drawing = true;
        } else {
          drawing = false;
        }
      }
    }

    final rings = Path(), ribs = Path();
    for (final depth in _ringDepths) {
      trace(rings, 160, ring: depth);
    }
    for (var i = 0; i < 66; i++) {
      trace(ribs, 85, ribAngle: i / 66 * _turn);
    }
    final mesh = Paint()
      ..style = PaintingStyle.stroke
      ..shader = ui.Gradient.radial(
        eye,
        w * 0.85,
        [
          mint.withValues(alpha: dark ? 0.62 : 0.57),
          mint.withValues(alpha: dark ? 0.27 : 0.25),
          (dark ? const Color(0xff3a6564) : const Color(0xff9bbcb5)).withValues(
            alpha: 0.48,
          ),
          (dark ? const Color(0xff2b4145) : const Color(0xffaebfbc)).withValues(
            alpha: 0.31,
          ),
        ],
        const [0, 0.15, 0.48, 1],
      );
    canvas.drawPath(rings, mesh..strokeWidth = 0.77);
    canvas.drawPath(ribs, mesh..strokeWidth = 0.7);

    final rand = _random(13);
    final particle = Paint();
    for (var i = 0; i < 75; i++) {
      final f = (rand() + phase) % 1;
      final p = point(_VortexDepth(0.07 + f * 0.48), rand() * _turn);
      final d = 0.6 + rand() * 1.15;
      final color = rand() > 0.83 ? gold : mint;
      canvas.drawOval(
        Rect.fromLTWH(p.dx, p.dy, d, d),
        particle..color = color.withValues(alpha: math.sin(f * math.pi) * 0.65),
      );
    }
  }

  void _paintTunnel(Canvas canvas, Size size) {
    final w = size.width, h = size.height;
    final mid = w * 0.53, y = h * 0.45;
    final mint = _mint, gold = _gold;
    canvas.drawRect(
      Offset.zero & size,
      Paint()
        ..shader = ui.Gradient.radial(
          Offset(mid, y + h * 0.12),
          w * 0.52,
          [
            mint.withValues(alpha: dark ? 0.16 : 0.10),
            mint.withValues(alpha: 0.03),
            mint.withValues(alpha: 0),
          ],
          const [0, 0.5, 1],
        ),
    );

    double centerY(double t) => y + h * 0.60 * math.pow(2, 10 * t - 10);
    var clipDepth = 0.0, lowest = double.infinity;
    for (var i = 0; i <= 100; i++) {
      final t = i / 100;
      final bottom = centerY(t) + h * 0.82 * (1 - t);
      if (bottom < lowest) {
        clipDepth = t;
        lowest = bottom;
      }
    }
    final clipW = w * 0.83 * (1 - clipDepth);
    final clipH = h * 0.82 * (1 - clipDepth);
    final clipY = centerY(clipDepth);
    final rim = Rect.fromCenter(
      center: Offset(mid, clipY),
      width: 2 * clipW,
      height: 2 * clipH,
    );

    final outer = Path(), inner = Path();
    for (var i = 0; i <= 24; i++) {
      final t = i / 25;
      (t <= clipDepth ? outer : inner).addOval(
        Rect.fromCenter(
          center: Offset(mid, centerY(t)),
          width: 2 * w * 0.83 * (1 - t),
          height: 2 * h * 0.82 * (1 - t),
        ),
      );
    }
    for (var i = 0; i < 64; i++) {
      final angle = i / 64 * _turn;
      final rx = math.cos(angle) * w * 0.83;
      final ry = math.sin(angle) * h * 0.82;
      var p = Offset(mid + rx, centerY(0) + ry);
      for (var j = 0; j < 65; j++) {
        final t = (j + 1) / 65;
        final q = Offset(mid + rx * (1 - t), centerY(t) + ry * (1 - t));
        final dx = (q.dx - mid) / clipW, dy = (q.dy - clipY) / clipH;
        if (j / 65 <= clipDepth ||
            dx * dx + dy * dy <= 1 ||
            (dy < 0 && dx.abs() <= 1)) {
          outer.moveTo(p.dx, p.dy);
          outer.lineTo(q.dx, q.dy);
        }
        p = q;
      }
    }
    final mesh = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 0.65
      ..color = (dark ? const Color(0xff4b7374) : const Color(0xff91aba8))
          .withValues(alpha: 0.65);
    canvas.drawPath(outer, mesh);
    canvas.save();
    canvas.clipPath(
      Path()
        ..addOval(rim)
        ..addRect(Rect.fromLTRB(mid - clipW, -h, mid + clipW, clipY)),
    );
    canvas.drawPath(inner, mesh);
    canvas.restore();

    final rand = _random(37);
    final particle = Paint();
    for (var i = 0; i < 50; i++) {
      final f = rand();
      final x = mid + (rand() - 0.5) * clipW * (2 - f);
      final y = clipY + clipH * 0.7 - f * h * 0.66;
      final d = rand() * 1.3 + 0.75;
      final color = rand() > 0.86 ? gold : mint;
      canvas.drawOval(
        Rect.fromLTWH(x, y, d, d),
        particle..color = color.withValues(alpha: rand() * 0.68 + 0.18),
      );
    }
  }

  @override
  bool shouldRepaint(covariant _VortexPainter oldDelegate) =>
      oldDelegate.dark != dark ||
      oldDelegate.locked != locked ||
      oldDelegate.cycle != cycle;
}
