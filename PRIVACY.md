# Privacy Policy / プライバシーポリシー

[English](#english) | [日本語](#日本語)

---

## English

**vTOTP (Vault-secured TOTP)** is designed as a local-first, privacy-focused command-line tool. We respect your privacy and are committed to protecting it.

### 1. Information Collection and Storage
- **No Telemetry or Analytics:** vTOTP does not collect, record, or transmit any user activity, usage statistics, crash logs, or telemetry data.
- **Local Operation by Application:** All operations and data handling by vTOTP—including configuration files, TOTP secrets, account labels, and encryption keys—are performed locally on your device.
- **Zero Network Transmission by vTOTP:** vTOTP does not initiate any inbound or outbound network connections. The tool itself will never transmit your secrets, keys, or data over the network.
- **User-Configured Storage and Synchronization:** If you choose to place configuration or master key files in cloud-synchronized directories (such as Microsoft OneDrive Personal Vault) or network-attached storage, file synchronization is governed solely by those external services and their respective privacy policies, independent of vTOTP.

### 2. Third-Party Services
- vTOTP does not integrate any third-party tracking, advertising, or analytics libraries.

### 3. Contact & Inquiries
If you have questions or concerns regarding this policy, please open an issue on GitHub:
- https://github.com/hammer-app/vtotp-cli/issues

---

## 日本語

**vTOTP（Vault-secured TOTP）** は、ユーザーのプライバシー保護を最優先に設計されたローカル完結型の CLI ツールです。

### 1. 情報の収集および保存について
- **テレメトリ・解析の不使用:** vTOTP は、ユーザーの利用履歴、使用状況統計、クラッシュログ、テレメトリ情報などを収集・記録・外部送信することは一切ありません。
- **アプリケーションのローカル完結:** vTOTP が扱うすべてのデータ（設定ファイル、TOTP シークレット、アカウント識別情報、暗号化キー）は、本ツールによってローカル環境（ご利用端末）内でのみ処理・保存されます。
- **vTOTP 自体の外部通信非実行:** vTOTP は外部ネットワークへの通信機能を備えていません。本ツール自身がシークレットや暗号鍵を外部へ送信することは一切ありません。
- **外部ストレージ・クラウド同期のご利用について:** ユーザーご自身の判断で Microsoft OneDrive の個人用 Vault や各種ネットワークドライブ等の同期対象フォルダに鍵や設定を配置された場合、ファイルの同期・転送は各サードパーティサービスの機能および利用規約に基づいて行われ、vTOTP の制御範囲外となります。

### 2. サードパーティ製サービスについて
- 本ツールには、サードパーティ製のトラッキングツール、広告配信ライブラリ、アクセス解析コード等は一切含まれていません。

### 3. お問い合わせ
本ポリシーに関するご質問や懸念がある場合は、GitHub の Issues にてお問い合わせください。
- https://github.com/hammer-app/vtotp-cli/issues
