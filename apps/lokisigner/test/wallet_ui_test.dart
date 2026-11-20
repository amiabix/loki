import 'dart:ui' show SemanticsAction;

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:loki_signer/main.dart';
import 'package:material_ui/material_ui.dart';

import 'fixture_wallet.dart';

void main() {
  Future<void> start(WidgetTester tester, FixtureWallet api) async {
    await tester.binding.setSurfaceSize(const Size(1040, 644));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(LokiApp(api: api, initialTheme: ThemeMode.light));
    await tester.pump();
  }

  Future<void> tap(WidgetTester tester, Finder finder) async {
    await tester.tap(finder);
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 350));
  }

  testWidgets(
    'History keeps its rows and only exposes the confirmed transaction externally',
    (tester) async {
      final api = FixtureWallet()..confirmed = false;
      String? copied;
      final messenger =
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
      messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
        if (call.method == 'Clipboard.setData') {
          copied = call.arguments['text'] as String;
        }
        return null;
      });
      addTearDown(
        () => messenger.setMockMethodCallHandler(SystemChannels.platform, null),
      );
      await start(tester, api);
      await tap(tester, find.text('History').first);
      await tap(tester, find.text('Awaiting confirmation'));
      expect(find.text('TRANSACTIONS'), findsOneWidget);
      expect(find.text('TRANSACTION DETAILS'), findsOneWidget);
      expect(find.byTooltip('Copy transaction id'), findsNothing);
      expect(find.text('View on ZecBlock'), findsNothing);

      api.confirmed = true;
      await tester.pump(const Duration(seconds: 3));
      await tester.pump();
      expect(find.text('TRANSACTIONS'), findsOneWidget);
      expect(find.text('View on ZecBlock'), findsOneWidget);
      await tester.ensureVisible(find.byTooltip('Copy transaction id'));
      await tester.pump();
      await tap(tester, find.byTooltip('Copy transaction id'));
      expect(copied, FixtureWallet.txid);
      expect(api.openedTx, isNull);
      await tester.ensureVisible(find.text('View on ZecBlock'));
      await tester.pump();
      await tap(tester, find.text('View on ZecBlock'));
      expect(api.openedTx, FixtureWallet.txid);
      await tester.ensureVisible(find.byTooltip('Close details'));
      await tester.pump();
      await tap(tester, find.byTooltip('Close details'));
      expect(find.text('TRANSACTIONS'), findsOneWidget);
      expect(find.text('TRANSACTION DETAILS'), findsNothing);
      await tester.pumpWidget(const SizedBox());
    },
  );

  testWidgets('Draft keeps exact zats and requires a separate publish', (
    tester,
  ) async {
    final api = FixtureWallet();
    await start(tester, api);
    await tap(tester, find.text('Studio vault').first);
    await tap(tester, find.text('Send').last);
    final fields = find.byType(TextField);
    await tester.enterText(fields.at(0), FixtureWallet.recipient);
    await tester.enterText(fields.at(1), '1.000000019');
    await tap(tester, find.text('Prepare draft'));
    expect(api.writes.where((e) => e.$1 == 'payment-draft'), isEmpty);

    await tester.enterText(fields.at(1), '0.00765431');
    await tap(tester, find.text('Prepare draft'));
    expect(
      api.writes.singleWhere((e) => e.$1 == 'payment-draft').$2['amount_zat'],
      '765431',
    );
    expect(api.writes.where((e) => e.$1 == 'payment-publish'), isEmpty);
    await tap(tester, find.text('Request approvals'));
    expect(
      api.writes.singleWhere((e) => e.$1 == 'payment-publish').$2['attempt'],
      'd' * 64,
    );
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets(
    'Proposal preview hands an exact reviewed intent to the signer only on Continue',
    (tester) async {
      final api = FixtureWallet();
      await start(tester, api);
      await tap(tester, find.text('Studio vault').first);
      await tap(tester, find.text('Review'));
      expect(find.text('Review this payment'), findsOneWidget);
      expect(api.writes.where((e) => e.$1 == 'payment-approve'), isEmpty);
      await tap(tester, find.text('Continue to signer'));
      expect(api.writes.singleWhere((e) => e.$1 == 'payment-approve').$2, {
        'vault': FixtureWallet.studio,
        'attempt': FixtureWallet.proposal,
        'review_token': 'f' * 64,
        'intent_hash': 'c' * 64,
      });
      expect(find.text('Approval requested'), findsOneWidget);
      await tester.pumpWidget(const SizedBox());
    },
  );

  testWidgets(
    'First launch sends only the entered origin to the native pairing flow',
    (tester) async {
      final api = FixtureWallet(running: false, fresh: true);
      await start(tester, api);
      expect(find.text('Set up your signer'), findsOneWidget);
      await tap(tester, find.text('Pair this Mac'));
      expect(api.pairOrigin, isNull);
      const origin = 'https://other.example:8443';
      await tester.enterText(find.byType(TextField), '  $origin  ');
      await tester.pump();
      expect(api.pairOrigin, isNull);
      await tap(tester, find.text('Continue'));
      expect(api.pairOrigin, origin);
      expect(find.text('All vaults'), findsWidgets);
      await tester.pumpWidget(const SizedBox());
    },
  );

  testWidgets(
    'The unlocked workspace shows the active signer’s pinned origin without a switch control',
    (tester) async {
      final api = FixtureWallet();
      final original = api.coordinator;
      const next = 'https://second-coordinator.example:8443';
      final semantics = tester.ensureSemantics();
      await start(tester, api);
      expect(find.text('Studio vault'), findsWidgets);
      expect(find.text(original), findsOneWidget);
      await tap(tester, find.text('Studio vault').first);
      expect(find.text(original), findsOneWidget);
      await tap(tester, find.text('Reserve vault').first);
      expect(find.text(original), findsOneWidget);
      await tap(tester, find.byTooltip('Lock signer'));
      expect(api.running, isFalse);
      expect(find.text('Studio vault'), findsNothing);
      expect(find.text('Paired coordinator'), findsNothing);
      expect(find.text(original), findsNothing);

      api.coordinator = next;
      await tap(tester, find.text('Unlock signer'));
      expect(find.text('Studio vault'), findsWidgets);
      expect(find.text(original), findsNothing);
      final displayedOrigin = find.text(next);
      expect(displayedOrigin, findsOneWidget);
      expect(
        tester
            .getSemantics(displayedOrigin)
            .getSemanticsData()
            .hasAction(SemanticsAction.tap),
        isFalse,
      );
      semantics.dispose();
      api.writes.clear();
      await tap(tester, displayedOrigin);
      expect(find.byType(TextField), findsNothing);
      expect(api.writes, isEmpty);
      await tester.pumpWidget(const SizedBox());
    },
  );
}
