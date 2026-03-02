using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;
using Lurgle.Logging;
using Timer = System.Timers.Timer;

namespace Seq.Client.WindowsLogins
{
    public class EventLogListener
    {
        private static bool _isInteractive;
        private static Timer _heartbeatTimer;
        private static readonly DateTime ServiceStart = DateTime.Now;
        private static long _logonsDetected;
        private static long _nonInteractiveLogons;
        private static long _logonFailuresDetected;
        private static long _nonInteractiveFailures;
        private static long _logoffsDetected;
        private static long _nonInteractiveLogoffs;
        private static long _unhandledEvents;
        private static long _oldEvents;
        private static long _emptyEvents;
        private readonly CancellationTokenSource _cancel = new CancellationTokenSource();
        private EventLogQuery _eventLog;
        private volatile bool _started;
        private EventLogWatcher _watcher;

        public EventLogListener(int? expiry = null)
        {
            int eventExpiryTime;

            if (expiry != null)
                eventExpiryTime = (int) expiry;
            else
                eventExpiryTime = 600;

            EventList = new TimedEventBag(eventExpiryTime);
        }

        // ReSharper disable once FieldCanBeMadeReadOnly.Local
        public static TimedEventBag EventList { get; private set; }

        public void Start(bool isInteractive)
        {
            try
            {
                _isInteractive = isInteractive;
                Log.Level(LurgLevel.Debug).Add("Starting listener");

                //Build query based on configured options
                _eventLog = new EventLogQuery("Security", PathType.LogName, BuildEventQuery());
                _watcher = new EventLogWatcher(_eventLog);
                _watcher.EventRecordWritten += OnEntryWritten;
                _watcher.Enabled = true;

                _started = true;

                //Heartbeat timer that can be used to detect if the service is not running
                if (Config.HeartbeatInterval <= 0) return;
                //First heartbeat will be at a random interval between 2 and 10 seconds
                _heartbeatTimer = isInteractive
                    ? new Timer {Interval = 10000}
                    : new Timer {Interval = new Random().Next(2000, 10000)};
                _heartbeatTimer.Elapsed += ServiceHeartbeat;
                _heartbeatTimer.AutoReset = false;
                _heartbeatTimer.Start();
            }
            catch (Exception ex)
            {
                Log.Exception(ex).Add("Failed to start listener: {Message:l}", ex.Message);
            }
        }

        private static void ServiceHeartbeat(object sender, ElapsedEventArgs e)
        {
            Log.Level(LurgLevel.Debug)
                .AddProperty("ItemCount", EventList.Count)
                .AddProperty("LogonsDetected", _logonsDetected)
                .AddProperty("NonInteractiveLogons", _nonInteractiveLogons)
                .AddProperty("LogonFailuresDetected", _logonFailuresDetected)
                .AddProperty("NonInteractiveFailures", _nonInteractiveFailures)
                .AddProperty("LogoffsDetected", _logoffsDetected)
                .AddProperty("NonInteractiveLogoffs", _nonInteractiveLogoffs)
                .AddProperty("OldEvents", _oldEvents)
                .AddProperty("EmptyEvents", _emptyEvents)
                .AddProperty("UnhandledEvents", _unhandledEvents)
                .AddProperty("NextTime", DateTime.Now.AddMilliseconds(Config.HeartbeatInterval))
                .Add(
                    Config.IsDebug
                        ? "{AppName:l} Heartbeat [{MachineName:l}] - Event cache: {ItemCount}, Logons detected: {LogonsDetected}, " +
                          "Non-interactive logons: {NonInteractiveLogons}, Logon failures: {LogonFailuresDetected}, " +
                          "Non-interactive failures: {NonInteractiveFailures}, Logoffs: {LogoffsDetected}, " +
                          "Non-interactive logoffs: {NonInteractiveLogoffs}, Unhandled events: {UnhandledEvents}, " +
                          "Old events seen: {OldEvents}, Empty events: {EmptyEvents}, Next Heartbeat: {NextTime:H:mm:ss tt}"
                        : "{AppName:l} Heartbeat [{MachineName:l}] - Event cache: {ItemCount}, Next Heartbeat: {NextTime:H:mm:ss tt}");

            if (_heartbeatTimer.AutoReset) return;
            //Set the timer to the configured heartbeat interval after initial heartbeat
            _heartbeatTimer.AutoReset = true;
            _heartbeatTimer.Interval = Config.HeartbeatInterval;
            _heartbeatTimer.Start();
        }

        public void Stop()
        {
            try
            {
                if (!_started)
                    return;

                _cancel.Cancel();
                _watcher.Enabled = false;
                _watcher.Dispose();

                Log.Level(LurgLevel.Debug).Add("Listener stopped");
            }
            catch (Exception ex)
            {
                Log.Exception(ex).Add("Failed to stop listener: {Message:l}", ex.Message);
            }
        }

        private static async void OnEntryWritten(object sender, EventRecordWrittenEventArgs args)
        {
            try
            {
                //Ensure that events are new and have not been seen already. This addresses a scenario where event logs can repeatedly pass events to the handler.
                if (args.EventRecord != null && args.EventRecord.TimeCreated >= ServiceStart &&
                    !EventList.Contains(args.EventRecord.RecordId))
                    await Task.Run(() => HandleEventLogEntry(args.EventRecord));
                else if (args.EventRecord != null && args.EventRecord.TimeCreated < ServiceStart)
                    _oldEvents++;
                else if (args.EventRecord == null)
                    _emptyEvents++;
            }
            catch (Exception ex)
            {
                Log.Exception(ex).Add("Failed to handle an event log entry: {Message:l}", ex.Message);
            }
        }

        private static void HandleEventLogEntry(EventRecord entry)
        {
            //Ensure that we track events we've already seen
            EventList.Add(entry.RecordId);

            try
            {
                switch (entry.Id)
                {
                    case 4624:
                        HandleLogonSuccessEvent(entry);
                        break;
                    case 4625:
                        HandleLogonFailureEvent(entry);
                        break;
                    case 4634:
                    case 4647:
                        HandleLogoffEvent(entry);
                        break;
                    default:
                        _unhandledEvents++;
                        break;
                }
            }
            catch (Exception ex)
            {
                Log.Exception(ex).Add("Error parsing event: {Message:l}", ex.Message);
            }
        }

        private static void HandleLogonSuccessEvent(EventRecord entry)
        {
            try
            {
                //Get all the properties of interest for passing to Seq
                var loginEventPropertySelector = new EventLogPropertySelector(new[]
                {
                    "Event/EventData/Data[@Name='SubjectUserSid']",
                    "Event/EventData/Data[@Name='SubjectUserName']",
                    "Event/EventData/Data[@Name='SubjectDomainName']",
                    "Event/EventData/Data[@Name='SubjectLogonId']",
                    "Event/EventData/Data[@Name='TargetUserSid']",
                    "Event/EventData/Data[@Name='TargetUserName']",
                    "Event/EventData/Data[@Name='TargetDomainName']",
                    "Event/EventData/Data[@Name='TargetLogonId']",
                    "Event/EventData/Data[@Name='LogonType']",
                    "Event/EventData/Data[@Name='LogonProcessName']",
                    "Event/EventData/Data[@Name='AuthenticationPackageName']",
                    "Event/EventData/Data[@Name='WorkstationName']",
                    "Event/EventData/Data[@Name='LogonGuid']",
                    "Event/EventData/Data[@Name='TransmittedServices']",
                    "Event/EventData/Data[@Name='LmPackageName']",
                    "Event/EventData/Data[@Name='KeyLength']",
                    "Event/EventData/Data[@Name='ProcessId']",
                    "Event/EventData/Data[@Name='ProcessName']",
                    "Event/EventData/Data[@Name='IpAddress']",
                    "Event/EventData/Data[@Name='IpPort']",
                    "Event/EventData/Data[@Name='ImpersonationLevel']"
                });

                var eventProperties = ((EventLogRecord) entry).GetPropertyValues(loginEventPropertySelector);

                if (eventProperties.Count != 21)
                {
                    _unhandledEvents++;
                    return;
                }

                if (IsNotValid(eventProperties))
                {
                    _nonInteractiveLogons++;
                    return;
                }

                _logonsDetected++;

                var eventTimeLong = string.Empty;
                var eventTimeShort = string.Empty;
                if (entry.TimeCreated != null)
                {
                    eventTimeLong = ((DateTime) entry.TimeCreated).ToString("F");
                    eventTimeShort = ((DateTime) entry.TimeCreated).ToString("G");
                }

                Log.Level(Extensions.MapLogLevel(EventLogEntryType.SuccessAudit))
                    .SetTimestamp(entry.TimeCreated ?? DateTime.Now)
                    .AddProperty("EventId", (long) entry.Id)
                    .AddProperty("InstanceId", entry.Id)
                    .AddProperty("EventTime", entry.TimeCreated)
                    .AddProperty("EventTimeLong", eventTimeLong)
                    .AddProperty("EventTimeShort", eventTimeShort)
                    .AddProperty("Source", entry.ProviderName)
                    .AddProperty("Category", entry.LevelDisplayName)
                    .AddProperty("EventLogName", entry.LogName)
                    .AddProperty("EventRecordID", entry.RecordId)
                    .AddProperty("Details", entry.FormatDescription())
                    .AddProperty("SubjectUserSid", eventProperties[0])
                    .AddProperty("SubjectUserName", eventProperties[1])
                    .AddProperty("SubjectDomainName", eventProperties[2])
                    .AddProperty("SubjectLogonId", eventProperties[3])
                    .AddProperty("TargetUserSid", eventProperties[4])
                    .AddProperty("TargetUserName", eventProperties[5])
                    .AddProperty("TargetDomainName", eventProperties[6])
                    .AddProperty("TargetLogonId", eventProperties[7])
                    .AddProperty("LogonType", eventProperties[8])
                    .AddProperty("LogonProcessName", eventProperties[9])
                    .AddProperty("AuthenticationPackageName", eventProperties[10])
                    .AddProperty("WorkstationName", eventProperties[11])
                    .AddProperty("LogonGuid", eventProperties[12])
                    .AddProperty("TransmittedServices", eventProperties[13])
                    .AddProperty("LmPackageName", eventProperties[14])
                    .AddProperty("KeyLength", eventProperties[15])
                    .AddProperty("ProcessId", eventProperties[16])
                    .AddProperty("ProcessName", eventProperties[17])
                    .AddProperty("IpAddress", eventProperties[18])
                    .AddProperty("IpPort", eventProperties[19])
                    .AddProperty("ImpersonationLevel", eventProperties[20])
                    .AddProperty(nameof(Config.ProjectKey), Config.ProjectKey)
                    .AddProperty(nameof(Config.Priority), Config.Priority)
                    .AddProperty(nameof(Config.Responders), Config.Responders)
                    .AddProperty(nameof(Config.Tags), Config.Tags)
                    .AddProperty(nameof(Config.InitialTimeEstimate), Config.InitialTimeEstimate)
                    .AddProperty(nameof(Config.RemainingTimeEstimate), Config.RemainingTimeEstimate)
                    .AddProperty(nameof(Config.DueDate), Config.DueDate)
                    .Add(
                        "[{AppName:l}] New login detected on {MachineName:l} - {TargetDomainName:l}\\{TargetUserName:l} at {EventTime:F}");
            }
            catch (Exception ex)
            {
                Log.Exception(ex).Add("Error parsing event: {Message:l}", ex.Message);
            }
        }

        private static void HandleLogonFailureEvent(EventRecord entry)
        {
            try
            {
                var failureEventPropertySelector = new EventLogPropertySelector(new[]
                {
                    "Event/EventData/Data[@Name='SubjectUserSid']",
                    "Event/EventData/Data[@Name='SubjectUserName']",
                    "Event/EventData/Data[@Name='SubjectDomainName']",
                    "Event/EventData/Data[@Name='SubjectLogonId']",
                    "Event/EventData/Data[@Name='TargetUserSid']",
                    "Event/EventData/Data[@Name='TargetUserName']",
                    "Event/EventData/Data[@Name='TargetDomainName']",
                    "Event/EventData/Data[@Name='Status']",
                    "Event/EventData/Data[@Name='FailureReason']",
                    "Event/EventData/Data[@Name='SubStatus']",
                    "Event/EventData/Data[@Name='LogonType']",
                    "Event/EventData/Data[@Name='LogonProcessName']",
                    "Event/EventData/Data[@Name='AuthenticationPackageName']",
                    "Event/EventData/Data[@Name='WorkstationName']",
                    "Event/EventData/Data[@Name='TransmittedServices']",
                    "Event/EventData/Data[@Name='LmPackageName']",
                    "Event/EventData/Data[@Name='KeyLength']",
                    "Event/EventData/Data[@Name='ProcessId']",
                    "Event/EventData/Data[@Name='ProcessName']",
                    "Event/EventData/Data[@Name='IpAddress']",
                    "Event/EventData/Data[@Name='IpPort']"
                });

                var eventProperties = ((EventLogRecord) entry).GetPropertyValues(failureEventPropertySelector);

                if (eventProperties.Count != 21)
                {
                    _unhandledEvents++;
                    return;
                }

                if (IsFailureNotValid(eventProperties))
                {
                    _nonInteractiveFailures++;
                    return;
                }

                _logonFailuresDetected++;

                var eventTimeLong = string.Empty;
                var eventTimeShort = string.Empty;
                if (entry.TimeCreated != null)
                {
                    eventTimeLong = ((DateTime) entry.TimeCreated).ToString("F");
                    eventTimeShort = ((DateTime) entry.TimeCreated).ToString("G");
                }

                Log.Level(Extensions.MapLogLevel(EventLogEntryType.FailureAudit))
                    .SetTimestamp(entry.TimeCreated ?? DateTime.Now)
                    .AddProperty("EventId", (long) entry.Id)
                    .AddProperty("InstanceId", entry.Id)
                    .AddProperty("EventTime", entry.TimeCreated)
                    .AddProperty("EventTimeLong", eventTimeLong)
                    .AddProperty("EventTimeShort", eventTimeShort)
                    .AddProperty("Source", entry.ProviderName)
                    .AddProperty("Category", entry.LevelDisplayName)
                    .AddProperty("EventLogName", entry.LogName)
                    .AddProperty("EventRecordID", entry.RecordId)
                    .AddProperty("Details", entry.FormatDescription())
                    .AddProperty("SubjectUserSid", eventProperties[0])
                    .AddProperty("SubjectUserName", eventProperties[1])
                    .AddProperty("SubjectDomainName", eventProperties[2])
                    .AddProperty("SubjectLogonId", eventProperties[3])
                    .AddProperty("TargetUserSid", eventProperties[4])
                    .AddProperty("TargetUserName", eventProperties[5])
                    .AddProperty("TargetDomainName", eventProperties[6])
                    .AddProperty("Status", eventProperties[7])
                    .AddProperty("FailureReason", eventProperties[8])
                    .AddProperty("SubStatus", eventProperties[9])
                    .AddProperty("LogonType", eventProperties[10])
                    .AddProperty("LogonProcessName", eventProperties[11])
                    .AddProperty("AuthenticationPackageName", eventProperties[12])
                    .AddProperty("WorkstationName", eventProperties[13])
                    .AddProperty("TransmittedServices", eventProperties[14])
                    .AddProperty("LmPackageName", eventProperties[15])
                    .AddProperty("KeyLength", eventProperties[16])
                    .AddProperty("ProcessId", eventProperties[17])
                    .AddProperty("ProcessName", eventProperties[18])
                    .AddProperty("IpAddress", eventProperties[19])
                    .AddProperty("IpPort", eventProperties[20])
                    .AddProperty(nameof(Config.ProjectKey), Config.ProjectKey)
                    .AddProperty(nameof(Config.Priority), Config.Priority)
                    .AddProperty(nameof(Config.Responders), Config.Responders)
                    .AddProperty(nameof(Config.Tags), Config.Tags)
                    .AddProperty(nameof(Config.InitialTimeEstimate), Config.InitialTimeEstimate)
                    .AddProperty(nameof(Config.RemainingTimeEstimate), Config.RemainingTimeEstimate)
                    .AddProperty(nameof(Config.DueDate), Config.DueDate)
                    .Add(
                        "[{AppName:l}] Login failure detected on {MachineName:l} - {TargetDomainName:l}\\{TargetUserName:l} at {EventTime:F}");
            }
            catch (Exception ex)
            {
                Log.Exception(ex).Add("Error parsing event: {Message:l}", ex.Message);
            }
        }

        private static void HandleLogoffEvent(EventRecord entry)
        {
            try
            {
                // Event 4647 (user-initiated logoff) has 4 properties; 4634 (logoff) has 5
                var isUserInitiated = entry.Id == 4647;
                var propertyNames = isUserInitiated
                    ? new[]
                    {
                        "Event/EventData/Data[@Name='TargetUserSid']",
                        "Event/EventData/Data[@Name='TargetUserName']",
                        "Event/EventData/Data[@Name='TargetDomainName']",
                        "Event/EventData/Data[@Name='TargetLogonId']"
                    }
                    : new[]
                    {
                        "Event/EventData/Data[@Name='TargetUserSid']",
                        "Event/EventData/Data[@Name='TargetUserName']",
                        "Event/EventData/Data[@Name='TargetDomainName']",
                        "Event/EventData/Data[@Name='TargetLogonId']",
                        "Event/EventData/Data[@Name='LogonType']"
                    };

                var logoffEventPropertySelector = new EventLogPropertySelector(propertyNames);
                var eventProperties = ((EventLogRecord) entry).GetPropertyValues(logoffEventPropertySelector);

                var expectedCount = isUserInitiated ? 4 : 5;
                if (eventProperties.Count != expectedCount)
                {
                    _unhandledEvents++;
                    return;
                }

                if (IsLogoffNotValid(eventProperties, isUserInitiated))
                {
                    _nonInteractiveLogoffs++;
                    return;
                }

                _logoffsDetected++;

                var eventTimeLong = string.Empty;
                var eventTimeShort = string.Empty;
                if (entry.TimeCreated != null)
                {
                    eventTimeLong = ((DateTime) entry.TimeCreated).ToString("F");
                    eventTimeShort = ((DateTime) entry.TimeCreated).ToString("G");
                }

                Log.Level(Extensions.MapLogLevel(EventLogEntryType.SuccessAudit))
                    .SetTimestamp(entry.TimeCreated ?? DateTime.Now)
                    .AddProperty("EventId", (long) entry.Id)
                    .AddProperty("InstanceId", entry.Id)
                    .AddProperty("EventTime", entry.TimeCreated)
                    .AddProperty("EventTimeLong", eventTimeLong)
                    .AddProperty("EventTimeShort", eventTimeShort)
                    .AddProperty("Source", entry.ProviderName)
                    .AddProperty("Category", entry.LevelDisplayName)
                    .AddProperty("EventLogName", entry.LogName)
                    .AddProperty("EventRecordID", entry.RecordId)
                    .AddProperty("Details", entry.FormatDescription())
                    .AddProperty("TargetUserSid", eventProperties[0])
                    .AddProperty("TargetUserName", eventProperties[1])
                    .AddProperty("TargetDomainName", eventProperties[2])
                    .AddProperty("TargetLogonId", eventProperties[3])
                    .AddProperty(nameof(Config.ProjectKey), Config.ProjectKey)
                    .AddProperty(nameof(Config.Priority), Config.Priority)
                    .AddProperty(nameof(Config.Responders), Config.Responders)
                    .AddProperty(nameof(Config.Tags), Config.Tags)
                    .AddProperty(nameof(Config.InitialTimeEstimate), Config.InitialTimeEstimate)
                    .AddProperty(nameof(Config.RemainingTimeEstimate), Config.RemainingTimeEstimate)
                    .AddProperty(nameof(Config.DueDate), Config.DueDate)
                    .Add(
                        "[{AppName:l}] Logoff detected on {MachineName:l} - {TargetDomainName:l}\\{TargetUserName:l} at {EventTime:F}");
            }
            catch (Exception ex)
            {
                Log.Exception(ex).Add("Error parsing event: {Message:l}", ex.Message);
            }
        }

        private static string BuildEventQuery()
        {
            var successEventIds = new List<string> {"EventID=4624"};

            if (Config.IncludeLogoffEvents)
            {
                successEventIds.Add("EventID=4634");
                successEventIds.Add("EventID=4647");
            }

            var successFilter =
                $"band(Keywords,9007199254740992) and ({string.Join(" or ", successEventIds)})";

            if (Config.IncludeLogonFailures)
                return
                    $"*[System[({successFilter}) or (band(Keywords,4503599627370496) and EventID=4625)]]";

            return $"*[System[{successFilter}]]";
        }

        public static bool IsNotValid(IList<object> eventProperties)
        {
            //Only interactive users are of interest - logonType 2 and 10. Some non-interactive services can launch processes with logontype 2 but can be filtered.
            //Note: LogonGuid is intentionally not checked here; on standalone servers using NTLM it is always all-zeros, which would incorrectly suppress RDP (type 10) logons.
            return ((uint) eventProperties[8] != 2 && (uint) eventProperties[8] != 10) ||
                   (string) eventProperties[18] == "-";
        }

        public static bool IsFailureNotValid(IList<object> eventProperties)
        {
            //Only interactive users are of interest - logonType 2 and 10 (LogonType is at index 10 in event 4625)
            return ((uint) eventProperties[10] != 2 && (uint) eventProperties[10] != 10) ||
                   (string) eventProperties[19] == "-";
        }

        public static bool IsLogoffNotValid(IList<object> eventProperties, bool isUserInitiated)
        {
            //For event 4647 (user-initiated logoff) there is no LogonType field; always include it.
            //For event 4634, only interactive logon types 2 and 10 are of interest (LogonType is at index 4).
            return !isUserInitiated &&
                   (uint) eventProperties[4] != 2 && (uint) eventProperties[4] != 10;
        }
    }
}