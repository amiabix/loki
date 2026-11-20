import 'dart:async';
import 'dart:ui' show ImageFilter;

import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import 'design.dart';
import 'payments.dart';
import 'vaults.dart';
import 'vortex.dart';
import 'wallet_api.dart';

void main() => runApp(const LokiApp(api: MacWalletApi()));

class LokiApp extends StatefulWidget {
  const LokiApp({
    super.key,
    required this.api,
    this.initialTheme = ThemeMode.system,
  });
  final WalletApi api;
  final ThemeMode initialTheme;

  @override
  State<LokiApp> createState() => _LokiAppState();
}

class _LokiAppState extends State<LokiApp> {
  late ThemeMode theme = widget.initialTheme;

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'LokiSigner',
    debugShowCheckedModeBanner: false,
    theme: lokiTheme(false),
    darkTheme: lokiTheme(true),
    themeMode: theme,
    home: _Wallet(
      api: widget.api,
      theme: theme,
      setTheme: (mode) async {
        setState(() => theme = mode);
        await widget.api.appearance(mode.name);
      },
    ),
  );
}

enum _Page {
  vaults,
  overview,
  setup,
  send,
  approvals,
  history,
  receive,
  recovery,
}

class _Wallet extends StatefulWidget {
  const _Wallet({
    required this.api,
    required this.theme,
    required this.setTheme,
  });
  final WalletApi api;
  final ThemeMode theme;
  final Future<void> Function(ThemeMode) setTheme;

  @override
  State<_Wallet> createState() => _WalletState();
}

class _WalletState extends State<_Wallet> {
  WalletApi get api => widget.api;
  Timer? timer;
  bool polling = false,
      busy = false,
      reviewing = false,
      loaded = false,
      open = false,
      locking = false;
  int generation = 0;
  Json profile = {};
  List<Json> vaults = [], payments = [], addresses = [];
  List<({Json vault, Json payment})> approvals = [];
  Json ceremony = {}, recovery = {};
  Object? balance;
  String? vaultId,
      selection,
      actionError,
      loadError,
      dataError,
      scanError,
      coordinator;
  DateTime nextScan = DateTime.fromMillisecondsSinceEpoch(0);
  final verifyUntil = <String, DateTime>{};
  bool scanning = false, enteringOrigin = false;
  String pairingOrigin = '';
  _Page page = _Page.vaults;

  Json? get vault => vaults.where((v) => v['vault'] == vaultId).firstOrNull;

  @override
  void initState() {
    super.initState();
    unawaited(poll());
  }

  @override
  void dispose() {
    timer?.cancel();
    super.dispose();
  }

  void resetSession() {
    generation++;
    open = false;
    page = _Page.vaults;
    vaults = [];
    approvals = [];
    addresses = [];
    payments = [];
    ceremony = {};
    recovery = {};
    balance = null;
    vaultId = selection = dataError = scanError = coordinator = null;
    verifyUntil.clear();
    nextScan = DateTime.fromMillisecondsSinceEpoch(0);
  }

  Future<void> poll() async {
    if (polling || !mounted) return;
    polling = true;
    timer?.cancel();
    final epoch = generation;
    try {
      final current = await api.profile();
      if (!mounted || locking || epoch != generation) return;
      if (current['running'] != true) {
        setState(() {
          if (open) resetSession();
          profile = current;
          loaded = true;
          loadError = null;
        });
        return;
      }
      final status = await api.request('status');
      if (!mounted || locking || epoch != generation) return;
      if (status['phase'] != 'home' || status['network'] != 'testnet') {
        setState(() {
          if (open) resetSession();
          loaded = true;
          profile = current;
          loadError = status['network'] != 'testnet'
              ? 'This app only supports Zcash testnet.'
              : null;
        });
        return;
      }
      final list = jsonRows(status['vaults']);
      setState(() {
        profile = current;
        loaded = open = true;
        loadError = null;
        coordinator = status['paired_coordinator'] as String?;
        vaults = list;
        vaultId ??=
            (list.where((v) => v['active'] == true).firstOrNull ??
                    list.firstOrNull)?['vault']
                as String?;
        if (page == _Page.setup && vault?['active'] == true) {
          page = _Page.overview;
        }
      });
      final active = vault?['active'] == true;
      final id = vaultId;
      final view = page;
      if (id != null &&
          active &&
          view == _Page.overview &&
          DateTime.now().isAfter(nextScan)) {
        unawaited(scan(id, epoch));
      }
      // Fetch the selected vault's data first; another vault's relay can't stall setup.
      if (id != null && view == _Page.setup && !active) {
        final result = await api.request('status?vault=$id');
        if (mounted && epoch == generation) {
          setState(() {
            ceremony = result;
            dataError = null;
          });
        }
      } else if (id != null &&
          active &&
          (view == _Page.history || view == _Page.overview)) {
        final result = jsonRows(
          (await api.request('payments?vault=$id'))['payments'],
        );
        if (!mounted || epoch != generation) return;
        setState(() {
          payments = result;
          dataError = null;
        });
        if (!scanning) unawaited(verifyBroadcast(id, result));
      }
      if (id != null && active && view == _Page.recovery) {
        final result = await api.request('recovery-status?vault=$id');
        if (mounted && epoch == generation) {
          setState(() {
            recovery = result;
            dataError = null;
          });
        }
      }
      if (view == _Page.approvals ||
          view == _Page.overview ||
          view == _Page.vaults) {
        final inbox = await Future.wait(
          list.where((v) => v['active'] == true).map((v) async {
            final rows = await api.request('pending?vault=${v['vault']}');
            return jsonRows(rows['pending']).map((p) => (vault: v, payment: p));
          }),
        );
        if (mounted && epoch == generation) {
          setState(() {
            approvals = inbox.expand((rows) => rows).toList();
            dataError = null;
          });
        }
      }
    } catch (e) {
      if (!mounted || locking || epoch != generation) return;
      if (e is PlatformException && e.code == '401') {
        setState(resetSession);
      } else {
        setState(() {
          loaded = true;
          if (open) {
            dataError = walletError(e);
          } else {
            loadError = walletError(e);
          }
        });
      }
    } finally {
      polling = false;
      if (mounted) timer = Timer(const Duration(seconds: 2), poll);
    }
  }

  Future<void> scan(String id, int epoch) async {
    if (scanning) return;
    scanning = true;
    nextScan = DateTime.now().add(const Duration(seconds: 10));
    try {
      final result = await api.request('balance', {'vault': id});
      if (mounted && epoch == generation) {
        setState(() {
          balance = result['balance_zat'];
          scanError = null;
        });
      }
    } catch (_) {
      if (mounted && epoch == generation) {
        setState(() => scanError = 'Balance could not sync. Retrying…');
      }
    } finally {
      scanning = false;
    }
  }

  Future<void> verifyBroadcast(String id, List<Json> result) async {
    final now = DateTime.now();
    final waiting = result.where(
      (p) => p['phase'] == 'broadcast' && p['txid'] != null,
    );
    final payment = waiting
        .where(
          (p) => verifyUntil
              .putIfAbsent(
                '$id/${p['attempt']}',
                () => now.add(const Duration(minutes: 1)),
              )
              .isAfter(now),
        )
        .firstOrNull;
    if (payment == null) return;
    scanning = true;
    try {
      await api.request('payment-verify', {
        'vault': id,
        'attempt': payment['attempt'],
        'txid': payment['txid'],
      });
    } catch (_) {
      // A missing confirmation is expected on testnet. History must keep 'Broadcast'.
    } finally {
      scanning = false;
    }
  }

  void go(_Page next, {String? id, String? attempt}) {
    setState(() {
      generation++;
      actionError = dataError = null;
      if (id != null && id != vaultId) {
        vaultId = id;
        balance = null;
        payments = [];
        ceremony = recovery = {};
        scanError = null;
        nextScan = DateTime.fromMillisecondsSinceEpoch(0);
      }
      if (next == _Page.history && page != _Page.history) verifyUntil.clear();
      page = next;
      selection = attempt;
    });
    unawaited(poll());
  }

  Future<void> act(Future<void> Function() perform) async {
    if (busy) return;
    setState(() {
      busy = true;
      actionError = null;
    });
    try {
      await perform();
    } catch (e) {
      if (mounted) setState(() => actionError = walletError(e));
    } finally {
      if (mounted) {
        setState(() => busy = false);
        unawaited(poll());
      }
    }
  }

  Future<void> lock() => act(() async {
    setState(() {
      locking = true;
      resetSession();
    });
    try {
      await api.lock();
    } finally {
      locking = false;
    }
  });

  Future<void> showReview(Json target, String attempt) async {
    if (reviewing) return;
    setState(() => reviewing = true);
    try {
      await showPaymentReview(context, target, attempt, api.request);
    } finally {
      if (mounted) {
        setState(() => reviewing = false);
        unawaited(poll());
      }
    }
  }

  void openVault(Json v) => go(
    v['active'] == true ? _Page.overview : _Page.setup,
    id: v['vault'] as String,
  );

  Future<void> loadAddresses() => act(() async {
    final epoch = generation;
    final rows = await api.addresses();
    if (mounted && epoch == generation) setState(() => addresses = rows);
  });

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    final still =
        reviewing ||
        profile['reduce_motion'] == true ||
        page == _Page.send ||
        (page == _Page.history && selection != null);
    final fresh = profile['profile'] == 'fresh';
    return Scaffold(
      body: Stack(
        fit: StackFit.expand,
        children: [
          if (!open || !{_Page.vaults, _Page.setup}.contains(page))
            Vortex(
              dark: c.dark,
              still: still || fresh,
              locked: !open && !fresh,
            ),
          if (open)
            Row(
              children: [
                SizedBox(width: 204, child: sidebar()),
                Expanded(
                  child: Padding(
                    padding: const EdgeInsets.fromLTRB(26, 0, 26, 3),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        topBar(),
                        Expanded(
                          child: SingleChildScrollView(
                            key: ValueKey((page, vaultId)),
                            padding: const EdgeInsets.only(top: 17, bottom: 12),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.stretch,
                              children: [
                                content(),
                                if (actionError ?? dataError
                                    case final message?) ...[
                                  const SizedBox(height: 12),
                                  Notice(message),
                                ],
                              ],
                            ),
                          ),
                        ),
                        Padding(
                          padding: const EdgeInsets.symmetric(vertical: 12),
                          child: Row(
                            children: [
                              Icon(
                                Icons.shield_outlined,
                                color: c.muted,
                                size: 13,
                              ),
                              const SizedBox(width: 5),
                              Text(
                                'Secure Enclave',
                                style: lokiSans(10, color: c.muted),
                              ),
                              const SizedBox(width: 12),
                              Expanded(
                                child: coordinator == null
                                    ? const SizedBox.shrink()
                                    : Wrap(
                                        spacing: 5,
                                        crossAxisAlignment:
                                            WrapCrossAlignment.center,
                                        children: [
                                          Text(
                                            '·',
                                            style: lokiSans(10, color: c.muted),
                                          ),
                                          Text(
                                            'Paired coordinator',
                                            style: lokiSans(10, color: c.muted),
                                          ),
                                          Text(
                                            coordinator!,
                                            style: lokiMono(9, color: c.muted),
                                          ),
                                        ],
                                      ),
                              ),
                              const SizedBox(width: 10),
                              Text(
                                'Testnet funds only',
                                style: lokiSans(10, color: c.muted),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            )
          else if (fresh)
            signerSetup()
          else
            locked(),
          if (!open && !fresh)
            Positioned(top: 4, right: 22, child: appearance()),
        ],
      ),
    );
  }

  Widget appearance() => PopupMenuButton<ThemeMode>(
    tooltip: 'Appearance',
    icon: Icon(Icons.contrast, size: 16, color: context.colors.muted),
    initialValue: widget.theme,
    onSelected: (mode) => act(() => widget.setTheme(mode)),
    itemBuilder: (_) => const [
      PopupMenuItem(value: ThemeMode.system, child: Text('Follow system')),
      PopupMenuItem(value: ThemeMode.light, child: Text('Light')),
      PopupMenuItem(value: ThemeMode.dark, child: Text('Dark')),
    ],
  );

  Widget topBar() {
    final c = context.colors;
    final crumb = switch (page) {
      _Page.setup => 'Vault setup',
      _Page.send => 'Send',
      _Page.history => 'History',
      _Page.receive => 'Vault addresses',
      _Page.recovery => 'Recovery',
      _Page.approvals => 'Approvals',
      _ => 'Wallet',
    };
    return SizedBox(
      height: 43,
      child: Row(
        children: [
          Icon(Icons.view_sidebar_outlined, size: 16, color: c.muted),
          Container(
            width: 1,
            height: 15,
            color: c.stroke,
            margin: const EdgeInsets.symmetric(horizontal: 12),
          ),
          Text('LokiSigner', style: lokiSans(12, weight: 600)),
          const SizedBox(width: 6),
          Icon(Icons.chevron_right, size: 13, color: c.muted),
          const SizedBox(width: 4),
          Text(crumb, style: lokiSans(12, color: c.muted)),
          const Spacer(),
          appearance(),
          Surface(
            radius: 14,
            color: c.panel.withValues(alpha: .85),
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
            child: Row(
              children: [
                Icon(Icons.circle, size: 5, color: c.mint),
                const SizedBox(width: 7),
                Text('TESTNET', style: lokiMono(9, spacing: 1.1)),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget sidebar() {
    final c = context.colors;
    Widget caption(String text) => Padding(
      padding: const EdgeInsets.fromLTRB(11, 0, 0, 8),
      child: LokiLabel(text, color: c.muted),
    );
    Widget nav(
      String title,
      IconData icon,
      bool selected,
      VoidCallback onTap, {
      int count = 0,
    }) => Semantics(
      selected: selected,
      child: Material(
        color: selected
            ? c.mint.withValues(alpha: c.dark ? .13 : .11)
            : Colors.transparent,
        borderRadius: BorderRadius.circular(9),
        clipBehavior: Clip.antiAlias,
        child: InkWell(
          onTap: onTap,
          child: Container(
            height: 35,
            padding: const EdgeInsets.symmetric(horizontal: 11),
            child: Row(
              children: [
                Icon(icon, size: 16, color: selected ? c.mint : c.muted),
                const SizedBox(width: 11),
                Expanded(
                  child: Text(
                    title,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: lokiSans(12, weight: selected ? 600 : 500),
                  ),
                ),
                if (count > 0)
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 6,
                      vertical: 3,
                    ),
                    decoration: BoxDecoration(
                      color: c.gold.withValues(alpha: .12),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Text('$count', style: lokiMono(9, color: c.gold)),
                  ),
              ],
            ),
          ),
        ),
      ),
    );
    final systemGlass = profile['liquid_glass'] == true;
    return Padding(
      padding: const EdgeInsets.all(8),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(17),
        child: Stack(
          fit: StackFit.expand,
          children: [
            if (systemGlass)
              const IgnorePointer(
                child: AppKitView(viewType: 'cash.loki/sidebar-glass'),
              ),
            BackdropFilter(
              enabled: !systemGlass,
              filter: ImageFilter.blur(sigmaX: 22, sigmaY: 22),
              child: DecoratedBox(
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(17),
                  border: Border.all(color: c.stroke),
                  gradient: systemGlass
                      ? null
                      : LinearGradient(
                          begin: Alignment.topLeft,
                          end: Alignment.bottomRight,
                          colors: [
                            (c.dark ? c.panel : Colors.white).withValues(
                              alpha: .76,
                            ),
                            c.bg.withValues(alpha: .86),
                          ],
                        ),
                ),
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Expanded(
                        child: SingleChildScrollView(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.stretch,
                            children: [
                              Padding(
                                padding: const EdgeInsets.only(
                                  top: 46,
                                  left: 11,
                                ),
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    const Brand(),
                                    const SizedBox(height: 4),
                                    Text(
                                      'Shielded multisig',
                                      style: lokiSans(12, color: c.muted),
                                    ),
                                  ],
                                ),
                              ),
                              const SizedBox(height: 30),
                              caption('Workspace'),
                              nav(
                                'All vaults',
                                Icons.layers_outlined,
                                page == _Page.vaults,
                                () => go(_Page.vaults),
                              ),
                              nav(
                                'Approvals',
                                Icons.inbox_outlined,
                                page == _Page.approvals,
                                () => go(_Page.approvals),
                                count: approvals.length,
                              ),
                              nav(
                                'History',
                                Icons.history,
                                page == _Page.history,
                                () => go(_Page.history),
                              ),
                              const SizedBox(height: 22),
                              caption('Vaults'),
                              for (final v in vaults)
                                nav(
                                  vaultName(v),
                                  v['active'] == true
                                      ? Icons.lock_outline
                                      : Icons.pending_outlined,
                                  v['vault'] == vaultId &&
                                      {
                                        _Page.overview,
                                        _Page.setup,
                                        _Page.send,
                                      }.contains(page),
                                  () => openVault(v),
                                ),
                              const SizedBox(height: 22),
                              caption('Signer'),
                              nav(
                                'Vault addresses',
                                Icons.qr_code,
                                page == _Page.receive,
                                () => go(_Page.receive),
                              ),
                              nav(
                                'Recovery',
                                Icons.key_outlined,
                                page == _Page.recovery,
                                () => go(_Page.recovery),
                              ),
                            ],
                          ),
                        ),
                      ),
                      const Divider(),
                      const SizedBox(height: 11),
                      Row(
                        children: [
                          CircleAvatar(
                            radius: 16,
                            backgroundColor: c.secondary,
                            child: Icon(
                              Icons.person_outline,
                              color: c.ink,
                              size: 17,
                            ),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  profile['slot'] == null
                                      ? 'Member'
                                      : 'Member ${profile['slot']}',
                                  style: lokiSans(12, weight: 600),
                                ),
                                Text(
                                  'This Mac',
                                  style: lokiSans(10, color: c.muted),
                                ),
                              ],
                            ),
                          ),
                          IconButton(
                            onPressed: busy ? null : lock,
                            tooltip: 'Lock signer',
                            icon: Icon(
                              Icons.lock_outline,
                              size: 15,
                              color: c.muted,
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget signerSetup() {
    final c = context.colors;
    final actions = busy
        ? null
        : () => setState(() {
            enteringOrigin = true;
            actionError = null;
          });
    final originSubmit = busy || pairingOrigin.trim().isEmpty
        ? null
        : () => act(() => api.pair(pairingOrigin.trim()));
    return Column(
      children: [
        SizedBox(
          height: 43,
          child: Padding(
            padding: const EdgeInsets.only(left: 90, right: 24),
            child: Row(
              children: [
                Text('LokiSigner', style: lokiSans(12, weight: 600)),
                const SizedBox(width: 6),
                Icon(Icons.chevron_right, size: 13, color: c.muted),
                const SizedBox(width: 4),
                Text('Signer setup', style: lokiSans(12, color: c.muted)),
                const Spacer(),
                appearance(),
                const StatusPill('Testnet'),
              ],
            ),
          ),
        ),
        Expanded(
          child: Align(
            alignment: enteringOrigin
                ? Alignment.center
                : const Alignment(-.70, 0),
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(24),
              child: enteringOrigin
                  ? SizedBox(
                      width: 700,
                      child: Row(
                        children: [
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              spacing: 12,
                              children: [
                                const Brand(),
                                const SizedBox(height: 18),
                                const LokiLabel('Pair this Mac'),
                                for (final (i, label) in const [
                                  'Enter address',
                                  'Confirm coordinator',
                                  'Confirm member slot',
                                  'Review configuration',
                                ].indexed)
                                  Row(
                                    spacing: 9,
                                    children: [
                                      CircleAvatar(
                                        radius: 12,
                                        backgroundColor: i == 0
                                            ? c.mint
                                            : c.secondary,
                                        child: Text(
                                          '${i + 1}',
                                          style: lokiMono(
                                            10,
                                            color: i == 0 ? c.bg : c.muted,
                                          ),
                                        ),
                                      ),
                                      Flexible(
                                        child: Text(
                                          label,
                                          style: lokiSans(
                                            12,
                                            color: i == 0 ? c.ink : c.muted,
                                          ),
                                        ),
                                      ),
                                    ],
                                  ),
                              ],
                            ),
                          ),
                          SizedBox(
                            width: 448,
                            child: Surface(
                              padding: const EdgeInsets.all(22),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.stretch,
                                spacing: 13,
                                children: [
                                  const LokiLabel('Coordinator address'),
                                  Text(
                                    'Pair this Mac',
                                    style: lokiSans(
                                      27,
                                      weight: 600,
                                      spacing: -1,
                                    ),
                                  ),
                                  Text(
                                    'Enter the HTTPS address your vault organizer gave you. Leave out any page or path.',
                                    style: lokiSans(12, color: c.muted),
                                  ),
                                  LokiLabel(
                                    'Coordinator HTTPS origin',
                                    color: c.muted,
                                  ),
                                  TextFormField(
                                    initialValue: pairingOrigin,
                                    autofocus: true,
                                    readOnly: busy,
                                    autocorrect: false,
                                    enableSuggestions: false,
                                    style: lokiMono(13),
                                    onChanged: (text) => setState(() {
                                      pairingOrigin = text;
                                      actionError = null;
                                    }),
                                    decoration: const InputDecoration(
                                      hintText: 'https://wallet.example',
                                      prefixIcon: Icon(Icons.link, size: 17),
                                    ),
                                  ),
                                  Text(
                                    busy
                                        ? 'Complete the native signer prompts to continue.'
                                        : 'You’ll confirm the address before this Mac contacts it.',
                                    style: lokiSans(11, color: c.muted),
                                  ),
                                  if (actionError case final message?)
                                    Notice(message),
                                  const Divider(),
                                  Wrap(
                                    alignment: WrapAlignment.end,
                                    spacing: 8,
                                    children: [
                                      ActionChipButton(
                                        'Cancel',
                                        Icons.close,
                                        busy
                                            ? null
                                            : () => setState(() {
                                                enteringOrigin = false;
                                                actionError = null;
                                              }),
                                      ),
                                      ActionChipButton(
                                        'Continue',
                                        Icons.arrow_forward,
                                        originSubmit,
                                        primary: true,
                                      ),
                                    ],
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ],
                      ),
                    )
                  : SizedBox(
                      width: 464,
                      child: Surface(
                        padding: const EdgeInsets.all(32),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          spacing: 13,
                          children: [
                            const Brand(),
                            const SizedBox(height: 10),
                            const LokiHead(
                              'Shielded multisig',
                              'Set up your signer',
                              'Pair this Mac with your testnet coordinator, or restore a signer using your recovery words and backup.',
                            ),
                            if (actionError case final message?)
                              Notice(message),
                            Wrap(
                              spacing: 8,
                              runSpacing: 8,
                              children: [
                                ActionChipButton(
                                  'Pair this Mac',
                                  Icons.arrow_forward,
                                  actions,
                                  primary: true,
                                ),
                                ActionChipButton(
                                  'Restore signer',
                                  Icons.key_outlined,
                                  busy ? null : () => act(api.restore),
                                ),
                              ],
                            ),
                            const SizedBox(height: 14),
                            Row(
                              spacing: 7,
                              children: [
                                Icon(
                                  Icons.shield_outlined,
                                  color: c.muted,
                                  size: 15,
                                ),
                                Flexible(
                                  child: Text(
                                    'Your signing keys stay on this Mac.',
                                    style: lokiSans(11, color: c.muted),
                                  ),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),
                    ),
            ),
          ),
        ),
        Padding(
          padding: const EdgeInsets.fromLTRB(24, 12, 24, 16),
          child: Row(
            children: [
              Icon(Icons.laptop_mac, color: c.muted, size: 14),
              const SizedBox(width: 6),
              Text('This Mac', style: lokiSans(10, color: c.muted)),
              const Spacer(),
              Text('Testnet funds only', style: lokiSans(10, color: c.muted)),
            ],
          ),
        ),
      ],
    );
  }

  Widget locked() {
    final c = context.colors;
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: SizedBox(
          width: 356,
          child: Surface(
            padding: const EdgeInsets.all(28),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Brand(),
                const SizedBox(height: 15),
                const LokiLabel('Shielded multisig'),
                const SizedBox(height: 14),
                Text(
                  !loaded ? 'Opening LokiSigner…' : 'Unlock your signer',
                  style: lokiSans(26, weight: 600, spacing: -1),
                ),
                const SizedBox(height: 12),
                Text(
                  'Enter your local profile passphrase in the macOS prompt to open LokiSigner on this Mac.',
                  style: lokiSans(13, color: c.muted),
                ),
                if (actionError ?? loadError case final message?) ...[
                  const SizedBox(height: 12),
                  Notice(message),
                ],
                const SizedBox(height: 18),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Flexible(
                      child: Text(
                        'Testnet only',
                        style: lokiMono(9, color: c.muted),
                      ),
                    ),
                    const SizedBox(width: 6),
                    Flexible(
                      flex: 3,
                      child: ActionChipButton(
                        'Unlock signer',
                        Icons.lock_open,
                        busy || !loaded ? null : () => act(api.unlock),
                        primary: true,
                      ),
                    ),
                  ],
                ),
                if (busy)
                  const Padding(
                    padding: EdgeInsets.only(top: 12),
                    child: LinearProgressIndicator(minHeight: 2),
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget content() {
    final target = vault;
    return switch (page) {
      _Page.vaults => VaultLibrary(
        vaults: vaults,
        open: openVault,
        busy: busy,
        create: () => vaultForm(false),
        join: () => vaultForm(true),
      ),
      _Page.setup when target != null => VaultSetup(
        vault: target,
        status: ceremony,
        busy: busy,
        compare: () => act(() async {
          await api.request('agree', {
            'vault': vaultId,
            'fingerprint': ceremony['fingerprint'],
            'roster_code': ceremony['roster_code'],
          });
        }),
        startOver: () => vaultForm(false),
      ),
      _Page.send when target != null => SendPage(
        vault: target,
        request: api.request,
        back: () => go(_Page.overview),
        published: (attempt) => go(_Page.history, attempt: attempt),
      ),
      _Page.overview when target != null => overview(target),
      _Page.approvals => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const LokiHead(
            'Workspace',
            'Approvals',
            'Payments awaiting your approval.',
          ),
          const SizedBox(height: 22),
          if (approvals.isEmpty)
            const Notice('No payment proposals are waiting for you.'),
          for (final item in approvals) ...[
            proposal(item.vault, item.payment, showVault: true),
            const SizedBox(height: 9),
          ],
        ],
      ),
      _Page.history => HistoryPage(
        vault: target?['active'] == true ? target : null,
        payments: payments,
        selected: selection,
        select: (id) => setState(() => selection = id),
        request: api.request,
        explorer: api.explorer,
        review: (attempt) {
          if (target != null) unawaited(showReview(target, attempt));
        },
        refresh: poll,
      ),
      _Page.receive => receive(),
      _Page.recovery => recoveryPage(),
      _ => const Notice('Choose a vault from the sidebar.'),
    };
  }

  Future<void> vaultForm(bool join) async {
    final form = await showDialog<Json>(
      context: context,
      builder: (_) => VaultForm(join: join),
    );
    if (!mounted || form == null) return;
    await act(() async {
      final result = await api.request(join ? 'join' : 'create', form);
      if (!mounted) return;
      go(_Page.setup, id: result['vault'] as String);
    });
  }

  Widget overview(Json v) {
    final c = context.colors;
    final pending = approvals
        .where((a) => a.vault['vault'] == v['vault'])
        .toList();
    final recent = payments
        .where((p) => p['phase'] == 'confirmed')
        .take(2)
        .toList();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            Expanded(child: LokiHead('Active vault', vaultName(v))),
            StatusPill(policy(v)),
          ],
        ),
        const SizedBox(height: 17),
        Container(
          height: 155,
          padding: const EdgeInsets.symmetric(horizontal: 23),
          decoration: BoxDecoration(
            border: Border.all(color: c.stroke),
            borderRadius: BorderRadius.circular(16),
            gradient: LinearGradient(
              stops: const [0, .32, .68, 1],
              colors: [
                c.panel,
                c.panel,
                c.panel.withValues(alpha: .50),
                c.panel.withValues(alpha: .10),
              ],
            ),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const LokiLabel('Balance'),
              const SizedBox(height: 8),
              Row(
                crossAxisAlignment: CrossAxisAlignment.baseline,
                textBaseline: TextBaseline.alphabetic,
                children: [
                  Text(
                    balance == null ? '—' : amountTaz(balance),
                    style: lokiMono(40, bold: true, spacing: -2.7),
                  ),
                  const SizedBox(width: 9),
                  Text('TAZ', style: lokiMono(16, color: c.muted)),
                  if (scanError case final error?) ...[
                    const SizedBox(width: 12),
                    Flexible(
                      child: Text(error, style: lokiSans(11, color: c.muted)),
                    ),
                  ],
                ],
              ),
              const SizedBox(height: 9),
              Row(
                children: [
                  ActionChipButton(
                    'Send',
                    Icons.north_east,
                    () => go(_Page.send),
                    primary: true,
                  ),
                  const SizedBox(width: 8),
                  ActionChipButton(
                    'Receive',
                    Icons.south_west,
                    () => go(_Page.receive),
                  ),
                ],
              ),
            ],
          ),
        ),
        const SizedBox(height: 20),
        Row(
          children: [
            const LokiLabel('Approvals'),
            const SizedBox(width: 8),
            if (pending.isNotEmpty)
              StatusPill('${pending.length} pending', pending: true),
          ],
        ),
        const SizedBox(height: 9),
        if (pending.isEmpty)
          const Notice('No approvals waiting for this vault.')
        else
          for (final item in pending.take(2)) ...[
            proposal(item.vault, item.payment),
            const SizedBox(height: 6),
          ],
        const SizedBox(height: 15),
        Row(
          children: [
            const LokiLabel('Recent history'),
            const Spacer(),
            TextButton(
              onPressed: () => go(_Page.history),
              child: const Text('View history ›'),
            ),
          ],
        ),
        if (recent.isEmpty)
          const Notice('No confirmed payments yet.')
        else
          Surface(
            child: Column(
              children: [
                for (final p in recent) ...[
                  if (p != recent.first) const Divider(indent: 55),
                  InkWell(
                    onTap: () =>
                        go(_Page.history, attempt: p['attempt'] as String),
                    child: Padding(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 17,
                        vertical: 8,
                      ),
                      child: Row(
                        children: [
                          CircleAvatar(
                            radius: 15,
                            backgroundColor: c.secondary,
                            child: Icon(
                              Icons.north_east,
                              size: 14,
                              color: c.muted,
                            ),
                          ),
                          const SizedBox(width: 11),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  p['direction'] == 'received'
                                      ? 'Received'
                                      : 'Sent',
                                  style: lokiSans(12, weight: 600),
                                ),
                                Text(
                                  shortId(p['recipient'] as String? ?? ''),
                                  style: lokiMono(9, color: c.muted),
                                ),
                              ],
                            ),
                          ),
                          const StatusPill('Confirmed'),
                          const SizedBox(width: 18),
                          Text(
                            '${amountTaz(p['amount_zat'])} TAZ',
                            style: lokiMono(11),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
      ],
    );
  }

  Widget proposal(Json v, Json p, {bool showVault = false}) {
    final c = context.colors;
    return Surface(
      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
      child: Row(
        children: [
          CircleAvatar(
            radius: 18,
            backgroundColor: c.gold.withValues(alpha: .11),
            child: Icon(Icons.draw_outlined, color: c.gold, size: 17),
          ),
          const SizedBox(width: 13),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Payment proposal', style: lokiSans(13, weight: 600)),
                const SizedBox(height: 4),
                Text(
                  '${showVault ? '${vaultName(v)} · ' : ''}Proposed by Member ${p['proposer']}',
                  style: lokiSans(11, color: c.muted),
                ),
              ],
            ),
          ),
          Text(
            '${amountTaz(p['amount_zat'])} TAZ',
            style: lokiMono(13, bold: true, color: c.gold),
          ),
          const SizedBox(width: 15),
          ActionChipButton(
            'Review',
            Icons.arrow_forward,
            reviewing ? null : () => showReview(v, p['attempt'] as String),
          ),
        ],
      ),
    );
  }

  Widget receive() => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      const LokiHead(
        'Signer',
        'Vault addresses',
        'Receive addresses are verified by this Mac before copying.',
      ),
      const SizedBox(height: 20),
      Align(
        alignment: Alignment.centerLeft,
        child: ActionChipButton(
          'Verify addresses',
          Icons.shield_outlined,
          busy ? null : loadAddresses,
          primary: true,
        ),
      ),
      for (final row in addresses) ...[
        const SizedBox(height: 12),
        Surface(
          padding: const EdgeInsets.all(18),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                row['name'] as String? ?? 'Vault',
                style: lokiSans(15, weight: 600),
              ),
              const SizedBox(height: 8),
              if (row['address'] case final String address) ...[
                Text(
                  'Testnet · Member ${row['slot']}',
                  style: lokiSans(11, color: context.colors.muted),
                ),
                const SizedBox(height: 8),
                SelectableText(address, style: lokiMono(11)),
                const SizedBox(height: 12),
                ActionChipButton(
                  'Copy address',
                  Icons.copy_outlined,
                  () => act(() => copyText(context, address, 'Address copied')),
                ),
              ] else
                Text(
                  row['error'] as String? ??
                      'LokiSigner could not verify the receive address.',
                ),
            ],
          ),
        ),
      ],
    ],
  );

  Widget recoveryPage() {
    final v = vault;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const LokiHead(
          'Signer',
          'Recovery',
          'Keep each vault’s encrypted backup separate from your recovery words.',
        ),
        const SizedBox(height: 21),
        Surface(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const LokiLabel('Encrypted backup'),
              const SizedBox(height: 10),
              Text(
                v?['active'] == true
                    ? vaultName(v!)
                    : 'Choose an active vault to export a backup.',
              ),
              const SizedBox(height: 10),
              const Text(
                'The 24 words alone cannot recover a vault. Save the encrypted backup away from this Mac.',
              ),
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  ActionChipButton(
                    'Export encrypted backup',
                    Icons.download_outlined,
                    !busy && recovery['recovery_backup'] == true && v != null
                        ? () =>
                              act(() => api.exportBackup(v['vault'] as String))
                        : null,
                    primary: true,
                  ),
                  ActionChipButton(
                    'Restore a vault',
                    Icons.key_outlined,
                    busy ? null : () => act(api.restore),
                  ),
                ],
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class Brand extends StatelessWidget {
  const Brand({super.key});
  @override
  Widget build(BuildContext context) =>
      Text('LOKI', style: lokiSans(28, weight: 800, spacing: 5));
}

Future<void> copyText(
  BuildContext context,
  String value,
  String feedback,
) async {
  await Clipboard.setData(ClipboardData(text: value));
  if (context.mounted) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(feedback), duration: const Duration(seconds: 1)),
    );
  }
}
