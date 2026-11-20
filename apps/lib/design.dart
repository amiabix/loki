import 'package:material_ui/material_ui.dart';

class LokiColors {
  const LokiColors(this.dark);
  final bool dark;
  Color get bg => Color(dark ? 0xff0a0c10 : 0xfff6f7f9);
  Color get panel => Color(dark ? 0xff12151c : 0xffffffff);
  Color get secondary => Color(dark ? 0xff181c25 : 0xfff0f2f5);
  Color get ink => Color(dark ? 0xffe8eaf0 : 0xff0a0c10);
  Color get muted => Color(dark ? 0xff8b93a7 : 0xff5b6475);
  Color get mint => Color(dark ? 0xff2fd8a8 : 0xff0e9f78);
  Color get gold => Color(dark ? 0xffe8b44a : 0xff9d6b13);
  Color get stroke => Color(dark ? 0x16ffffff : 0x16000000);
}

extension Palette on BuildContext {
  LokiColors get colors =>
      LokiColors(Theme.of(this).brightness == Brightness.dark);
}

TextStyle lokiSans(
  double size, {
  double weight = 400,
  Color? color,
  double? spacing,
}) => TextStyle(
  fontFamily: 'Inter',
  fontSize: size,
  letterSpacing: spacing,
  color: color,
  fontVariations: [FontVariation('wght', weight)],
);

TextStyle lokiMono(
  double size, {
  bool bold = false,
  Color? color,
  double? spacing,
}) => TextStyle(
  fontFamily: 'Martian Mono',
  fontSize: size,
  letterSpacing: spacing,
  color: color,
  fontVariations: [
    FontVariation('wght', bold ? 600 : 400),
    const FontVariation('wdth', 112.5),
  ],
);

ThemeData lokiTheme(bool dark) {
  final c = LokiColors(dark);
  final scheme = ColorScheme.fromSeed(
    seedColor: c.mint,
    brightness: dark ? Brightness.dark : Brightness.light,
    surface: c.panel,
    onSurface: c.ink,
    primary: c.mint,
    onPrimary: const Color(0xff0a0c10),
  );
  final base = ThemeData(
    colorScheme: scheme,
    fontFamily: 'Inter',
    visualDensity: VisualDensity.compact,
  );
  return base.copyWith(
    scaffoldBackgroundColor: c.bg,
    textTheme: base.textTheme.apply(bodyColor: c.ink, displayColor: c.ink),
    dividerTheme: DividerThemeData(color: c.stroke, thickness: 1, space: 1),
    inputDecorationTheme: InputDecorationThemeData(
      filled: true,
      fillColor: c.secondary,
      isDense: true,
      contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 11),
      hintStyle: lokiSans(12, color: c.muted),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(10),
        borderSide: BorderSide(color: c.stroke),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(10),
        borderSide: BorderSide(color: c.stroke),
      ),
    ),
  );
}

class LokiLabel extends StatelessWidget {
  const LokiLabel(this.text, {super.key, this.color});
  final String text;
  final Color? color;
  @override
  Widget build(BuildContext context) => Text(
    text.toUpperCase(),
    style: lokiMono(9, color: color ?? context.colors.mint, spacing: 1.4),
  );
}

class LokiHead extends StatelessWidget {
  // This compact heading takes its optional subtitle as the third positional argument.
  // ignore: use_key_in_widget_constructors
  const LokiHead(this.kicker, this.title, [this.subtitle]);
  final String kicker, title;
  final String? subtitle;
  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    mainAxisSize: MainAxisSize.min,
    children: [
      LokiLabel(kicker),
      const SizedBox(height: 5),
      Semantics(
        header: true,
        child: Text(title, style: lokiSans(31, weight: 600, spacing: -1.4)),
      ),
      if (subtitle case final text?) ...[
        const SizedBox(height: 5),
        Text(text, style: lokiSans(12, color: context.colors.muted)),
      ],
    ],
  );
}

class Surface extends StatelessWidget {
  const Surface({
    super.key,
    required this.child,
    this.color,
    this.radius = 16,
    this.padding = EdgeInsets.zero,
  });
  final Widget child;
  final Color? color;
  final double radius;
  final EdgeInsetsGeometry padding;
  @override
  Widget build(BuildContext context) => Material(
    color: color ?? context.colors.panel,
    clipBehavior: Clip.antiAlias,
    shape: RoundedRectangleBorder(
      borderRadius: BorderRadius.circular(radius),
      side: BorderSide(color: context.colors.stroke),
    ),
    child: Padding(padding: padding, child: child),
  );
}

class ActionChipButton extends StatelessWidget {
  const ActionChipButton(
    this.title,
    this.icon,
    this.action, {
    super.key,
    this.primary = false,
  });
  final String title;
  final IconData icon;
  final VoidCallback? action;
  final bool primary;
  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return TextButton.icon(
      onPressed: action,
      icon: Icon(icon, size: 14),
      label: Text(title),
      style: TextButton.styleFrom(
        backgroundColor: primary ? c.mint : c.secondary,
        disabledBackgroundColor: c.secondary,
        foregroundColor: primary ? const Color(0xff0a0c10) : c.ink,
        minimumSize: const Size(0, 33),
        tapTargetSize: MaterialTapTargetSize.shrinkWrap,
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7),
        textStyle: lokiSans(12, weight: 600),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(11),
          side: BorderSide(color: c.stroke),
        ),
      ),
    );
  }
}

class StatusPill extends StatelessWidget {
  const StatusPill(this.title, {super.key, this.pending = false});
  final String title;
  final bool pending;
  @override
  Widget build(BuildContext context) {
    final color = pending ? context.colors.gold : context.colors.mint;
    return Container(
      height: 22,
      padding: const EdgeInsets.symmetric(horizontal: 9),
      decoration: BoxDecoration(
        color: color.withValues(alpha: .09),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.circle, size: 5, color: color),
          const SizedBox(width: 6),
          Text(title, style: lokiSans(10, weight: 500, color: color)),
        ],
      ),
    );
  }
}

class ValueRow extends StatelessWidget {
  const ValueRow(this.label, this.value, {super.key, this.mono = false});
  final String label, value;
  final bool mono;
  @override
  Widget build(BuildContext context) => Row(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Expanded(
        child: Text(label, style: lokiSans(12, color: context.colors.muted)),
      ),
      const SizedBox(width: 9),
      Expanded(
        child: Text(
          value,
          textAlign: TextAlign.end,
          style: mono ? lokiMono(11) : lokiSans(12, weight: 500),
        ),
      ),
    ],
  );
}

String shortId(String value) => value.length > 18
    ? '${value.substring(0, 10)}…${value.substring(value.length - 6)}'
    : value;
