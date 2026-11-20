import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import 'design.dart';
import 'wallet_api.dart';

String vaultName(Json vault) => vault['name'] as String? ?? 'Vault';
String policy(Json vault) =>
    '${vault['threshold']} of ${vault['members']} approvals';

class Notice extends StatelessWidget {
  const Notice(this.message, {super.key});
  final String message;
  @override
  Widget build(BuildContext context) => Surface(
    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
    child: Text(message, style: lokiSans(12, color: context.colors.muted)),
  );
}

class VaultLibrary extends StatelessWidget {
  const VaultLibrary({
    super.key,
    required this.vaults,
    required this.open,
    required this.busy,
    required this.create,
    required this.join,
  });
  final List<Json> vaults;
  final ValueChanged<Json> open;
  final bool busy;
  final VoidCallback create, join;

  @override
  Widget build(BuildContext context) {
    final active = vaults.where((v) => v['active'] == true);
    final setup = vaults.where((v) => v['active'] != true);
    final c = context.colors;
    Widget card(Json v, bool active) {
      final tint = active ? c.mint : c.gold;
      return Surface(
        child: InkWell(
          onTap: () => open(v),
          child: Padding(
            padding: const EdgeInsets.all(18),
            child: Row(
              children: [
                Container(
                  width: 46,
                  height: 46,
                  decoration: BoxDecoration(
                    color: tint.withValues(alpha: .10),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Icon(
                    active ? Icons.lock_outline : Icons.pending_outlined,
                    color: tint,
                    size: 22,
                  ),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        vaultName(v),
                        style: lokiSans(17, weight: 600, spacing: -.4),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        shortId(v['vault'] as String),
                        style: lokiMono(10, color: c.muted),
                      ),
                    ],
                  ),
                ),
                StatusPill(
                  active ? policy(v) : 'Set up vault',
                  pending: !active,
                ),
                const SizedBox(width: 8),
                Icon(Icons.chevron_right, color: c.muted, size: 16),
              ],
            ),
          ),
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            const Expanded(
              child: LokiHead(
                'Workspace',
                'All vaults',
                'Your active vaults and setups in progress on this Mac.',
              ),
            ),
            ActionChipButton('Join vault', Icons.link, busy ? null : join),
            const SizedBox(width: 8),
            ActionChipButton(
              'Create vault',
              Icons.add,
              busy ? null : create,
              primary: true,
            ),
          ],
        ),
        const SizedBox(height: 31),
        const LokiLabel('Active vaults'),
        const SizedBox(height: 10),
        if (active.isEmpty)
          const Notice(
            'No active vaults. Create a vault or join one with an invitation.',
          ),
        for (final v in active) ...[card(v, true), const SizedBox(height: 8)],
        if (setup.isNotEmpty) ...[
          const SizedBox(height: 18),
          const LokiLabel('Setting up'),
          const SizedBox(height: 10),
          for (final v in setup) ...[card(v, false), const SizedBox(height: 8)],
        ],
      ],
    );
  }
}

class VaultForm extends StatefulWidget {
  const VaultForm({super.key, required this.join});
  final bool join;
  @override
  State<VaultForm> createState() => _VaultFormState();
}

class _VaultFormState extends State<VaultForm> {
  final form = GlobalKey<FormState>();
  String name = '', invite = '';
  int members = 3, threshold = 2;

  String get code =>
      Uri.tryParse(invite.trim())?.queryParameters['invite'] ?? invite.trim();

  @override
  Widget build(BuildContext context) {
    final joining = widget.join;
    return AlertDialog(
      title: Text(joining ? 'Join a vault' : 'Create a vault'),
      content: SizedBox(
        width: 400,
        child: Form(
          key: form,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                joining
                    ? 'Paste the invite link or code from the creator. Compare the roster with the other members before creating keys.'
                    : 'Choose how many members share custody and how many approvals a payment needs.',
              ),
              const SizedBox(height: 16),
              if (joining)
                TextFormField(
                  autofocus: true,
                  maxLines: 3,
                  autocorrect: false,
                  enableSuggestions: false,
                  decoration: const InputDecoration(
                    labelText: 'Invite link or code',
                  ),
                  onChanged: (text) => invite = text,
                  validator: (_) =>
                      code.isEmpty ? 'Paste an invitation.' : null,
                )
              else ...[
                TextFormField(
                  autofocus: true,
                  decoration: const InputDecoration(labelText: 'Vault name'),
                  onChanged: (value) => name = value.trim(),
                  validator: (_) =>
                      name.isEmpty || utf8.encode(name).length > 80
                      ? 'Enter a vault name of 1–80 bytes.'
                      : null,
                ),
                const SizedBox(height: 12),
                Row(
                  children: [
                    Expanded(
                      child: DropdownButton<int>(
                        value: members,
                        isExpanded: true,
                        items: [
                          for (var n = 3; n <= 16; n++)
                            DropdownMenuItem(
                              value: n,
                              child: Text('$n members'),
                            ),
                        ],
                        onChanged: (n) => setState(() {
                          members = n!;
                          if (threshold >= members) threshold = members - 1;
                        }),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: DropdownButton<int>(
                        value: threshold,
                        isExpanded: true,
                        items: [
                          for (var n = 2; n < members; n++)
                            DropdownMenuItem(
                              value: n,
                              child: Text('$n approvals'),
                            ),
                        ],
                        onChanged: (n) => setState(() => threshold = n!),
                      ),
                    ),
                  ],
                ),
              ],
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Cancel'),
        ),
        ActionChipButton(
          joining ? 'Join vault' : 'Create vault',
          joining ? Icons.link : Icons.add,
          () {
            if (form.currentState!.validate()) {
              Navigator.pop(
                context,
                joining
                    ? <String, dynamic>{'invite': code}
                    : <String, dynamic>{
                        'name': name,
                        'members': members,
                        'threshold': threshold,
                      },
              );
            }
          },
          primary: true,
        ),
      ],
    );
  }
}

class VaultSetup extends StatelessWidget {
  const VaultSetup({
    super.key,
    required this.vault,
    required this.status,
    required this.busy,
    required this.compare,
    required this.startOver,
  });
  final Json vault, status;
  final bool busy;
  final VoidCallback compare, startOver;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    final phase = status['phase'];
    final step = switch (phase) {
      'compare_roster' => 1,
      'creating_keys' => 2,
      'active' => 3,
      _ => 0,
    };
    const steps = ['Members', 'Verify members', 'Create keys', 'Active'];
    final invites = jsonRows(status['invites']);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        LokiHead(vaultName(vault), 'Set up vault'),
        const SizedBox(height: 18),
        Row(
          children: [
            for (var i = 0; i < steps.length; i++) ...[
              if (i != 0)
                const Expanded(
                  child: Padding(
                    padding: EdgeInsets.symmetric(horizontal: 8),
                    child: Divider(),
                  ),
                ),
              Icon(
                i < step
                    ? Icons.check_circle
                    : i == step
                    ? Icons.radio_button_checked
                    : Icons.radio_button_unchecked,
                size: 13,
                color: i <= step ? c.mint : c.muted,
              ),
              const SizedBox(width: 5),
              Text(
                steps[i],
                style: lokiSans(
                  11,
                  weight: i == step ? 600 : 400,
                  color: i == step ? c.ink : c.muted,
                ),
              ),
            ],
          ],
        ),
        const SizedBox(height: 18),
        if (phase == 'compare_roster')
          roster(context)
        else if (phase == 'creating_keys')
          const Notice(
            'Creating keys on the member devices. Keep LokiSigner open while the ceremony completes.',
          )
        else if (phase == 'setup_interrupted') ...[
          Notice(
            status['error'] as String? ?? 'Key generation was interrupted. Use a new vault and new invitations.',
          ),
          const SizedBox(height: 10),
          Align(
            alignment: Alignment.centerLeft,
            child: ActionChipButton(
              'Create a new vault',
              Icons.add,
              busy ? null : startOver,
              primary: true,
            ),
          ),
        ] else if (status.isEmpty)
          const Notice('Loading vault setup…')
        else ...[
          Notice(
            invites.isEmpty
                ? 'Waiting for the other members. Leave LokiSigner open to follow setup.'
                : 'Give each member their own invite code over a trusted channel. They can paste it in Join vault.',
          ),
          for (final invite in invites) ...[
            const SizedBox(height: 8),
            Surface(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 9),
              child: Row(
                children: [
                  Text('Member ${invite['slot']}'),
                  const Spacer(),
                  if (invite['joined'] == true)
                    const StatusPill('Joined')
                  else if (invite['code'] case final String code)
                    ActionChipButton(
                      'Copy invite',
                      Icons.copy_outlined,
                      () async {
                        await Clipboard.setData(ClipboardData(text: code));
                        if (context.mounted) {
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(
                              content: Text('Invite copied'),
                              duration: Duration(seconds: 1),
                            ),
                          );
                        }
                      },
                    ),
                ],
              ),
            ),
          ],
        ],
      ],
    );
  }

  Widget roster(BuildContext context) {
    final c = context.colors;
    final code = (status['roster_code'] as String? ?? '').replaceAll(
      RegExp(r'\s'),
      '',
    );
    final groups = RegExp(r'^\d{24}$').hasMatch(code)
        ? RegExp(r'\d{4}').allMatches(code).map((m) => m.group(0)!).toList()
        : <String>[];
    final confirmed = status['confirmed'] == true;
    final refused = status['roster_dialog'] == 'codes_differ';
    final waiting = status['roster_dialog'] == 'open';
    return Surface(
      padding: const EdgeInsets.all(21),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const LokiLabel('Roster verification'),
          const SizedBox(height: 13),
          Text(
            'Do the roster codes match?',
            style: lokiSans(21, weight: 600, spacing: -.65),
          ),
          const SizedBox(height: 12),
          Text(
            'Compare all six groups with every member over a trusted channel, such as a phone call or in person.',
            style: lokiSans(13, color: c.muted),
          ),
          if (groups.isNotEmpty) ...[
            const SizedBox(height: 14),
            Row(
              children: [
                for (var i = 0; i < groups.length; i++) ...[
                  if (i != 0) const SizedBox(width: 6),
                  Expanded(
                    child: Surface(
                      color: c.secondary,
                      radius: 9,
                      padding: const EdgeInsets.symmetric(vertical: 15),
                      child: Text(
                        groups[i],
                        textAlign: TextAlign.center,
                        style: lokiMono(16, bold: true),
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ],
          const SizedBox(height: 14),
          const Divider(),
          const SizedBox(height: 12),
          ValueRow('Vault name (set by creator)', vaultName(vault)),
          const SizedBox(height: 9),
          ValueRow('Policy', policy(vault)),
          if (vault['my_slot'] case final int slot) ...[
            const SizedBox(height: 9),
            ValueRow('Your slot', 'Member $slot'),
          ],
          if (status['confirmations'] case final int count) ...[
            const SizedBox(height: 9),
            ValueRow('Confirmed here', '$count of ${vault['members']}'),
          ],
          const SizedBox(height: 13),
          const Divider(),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: Text(
                  refused
                      ? 'Codes differed. LokiSigner refuses this setup until it restarts.'
                      : confirmed
                      ? 'You confirmed. Waiting for the other members.'
                      : 'Choose Codes match or Codes differ in the native signer prompt.',
                  style: lokiSans(11, color: c.muted),
                ),
              ),
              if (!confirmed && !refused)
                ActionChipButton(
                  'Compare in LokiSigner',
                  Icons.shield_outlined,
                  busy ||
                          waiting ||
                          groups.isEmpty ||
                          status['fingerprint'] == null
                      ? null
                      : compare,
                  primary: true,
                ),
            ],
          ),
        ],
      ),
    );
  }
}
