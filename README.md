# Seq.Client.WindowsLogins

This Windows service started life as a fork of the [Seq.Client.EventLog](https://github.com/c0shea/Seq.Client.EventLog) app for [Seq](https://getseq.net/), but has diverged quite a long way; nonetheless it absolutely owes DNA to the original.

This substantially modifies the client to a service that looks for interactive user logins and raises a nicely formatted event with the data extracted as structured properties. It can optionally also capture logon failures and logoff events.

## Get Started

1. [Download the latest release](https://github.com/MattMofDoom/Seq.Client.WindowsLogins/releases) of Seq.Client.WindowsLogins.
2. Extract it to your preferred install directory.
3. Edit the ```Seq.Client.WindowsLogins.exe.config``` file, replacing the ```SeqUri``` with the URL of your Seq server. If you configured Seq to use API keys, also specify your key in the config file.
4. From the command line, run ```Seq.Client.WindowsLogins.exe /install```. This will install the Windows Service and set it to start automatically at boot.
5. From the command line, run ```net start Seq.Client.WindowsLogins``` to start the service.
6. Click the refresh button in Seq as you wait anxiously for the events to start flooding in!

## Configuration Options

The following options can be set in `Seq.Client.WindowsLogins.exe.config`:

| Setting | Default | Description |
|---|---|---|
| `AppName` | `Seq.Client.WindowsLogins` | App name used for logging |
| `LogSeqServer` | *(required)* | URL of your Seq server |
| `LogSeqApiKey` | *(empty)* | Seq API key (leave blank if not used) |
| `LogFolder` | *(app dir)* | Folder for local file logs |
| `HeartbeatInterval` | `600` | Heartbeat log interval in seconds (0 disables) |
| `IsDebug` | `false` | Include extra detail in heartbeat log entries |
| `IncludeLogonFailures` | `false` | Capture failed logon events (Event ID 4625) |
| `IncludeLogoffEvents` | `false` | Capture logoff events (Event IDs 4634 and 4647) |

### Notes on logon filtering

Interactive logons are identified by **LogonType 2** (console) and **LogonType 10** (Remote Desktop / RDP). Non-interactive logons (services, batch jobs, network shares, etc.) are excluded. This filtering applies equally to success, failure, and logoff events.

On **standalone servers** (not domain-joined), Windows uses NTLM rather than Kerberos, so the `LogonGuid` field in logon events is always all-zeros. The service correctly handles this and does **not** filter out events based on a zero `LogonGuid`.

## Enriched Events

Events are ingested into Seq with useful properties that allow for easy searching.

```
