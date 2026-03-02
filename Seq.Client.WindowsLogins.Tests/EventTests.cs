using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using Xunit;
using Xunit.Abstractions;

namespace Seq.Client.WindowsLogins.Tests
{
    public class EventTests
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public EventTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        /// <summary>
        ///     Ensure valid properties will be passed
        /// </summary>
        [Fact]
        public void EvaluatesValidEvent()
        {
            IList<object> test = new List<object>
            {
                "00000000-0000-0000-0000-000000000001", "Barry", "BARRY", "Barry",
                "00000000-0000-0000-0000-000000000001", "Barry", "BARRY", "Barry", (uint) 2, "Barry", "BarryAuth",
                "BARRYPC",
                Guid.Parse("00000000-0000-0000-0000-000000000001"), "Barries", "Barry", 1024, 1, " BARRY.EXE",
                "127.0.0.1", 1111,
                "All The Impersonation"
            };

            Assert.False(EventLogListener.IsNotValid(test));
        }

        /// <summary>
        ///     Ensure an RDP (type 10) logon with a zero LogonGuid is treated as valid.
        ///     On standalone servers using NTLM, LogonGuid is always all-zeros; the old check incorrectly filtered these out.
        /// </summary>
        [Fact]
        public void EvaluatesValidRdpEventWithZeroLogonGuid()
        {
            IList<object> test = new List<object>
            {
                "00000000-0000-0000-0000-000000000001", "Barry", "BARRY", "Barry",
                "00000000-0000-0000-0000-000000000001", "Barry", "BARRY", "Barry", (uint) 10, "Barry", "BarryAuth",
                "BARRYPC",
                Guid.Parse("00000000-0000-0000-0000-000000000000"), "Barries", "Barry", 1024, 1, " BARRY.EXE",
                "192.168.1.100", 3389,
                "Impersonation"
            };

            Assert.False(EventLogListener.IsNotValid(test));
        }

        /// <summary>
        ///     Ensure a type 7 (Unlock) logon with a remote IpAddress is treated as valid.
        ///     Reconnecting to an existing RDP session generates LogonType=7, not LogonType=10,
        ///     so this must be accepted when there is a remote source address.
        /// </summary>
        [Fact]
        public void EvaluatesValidRdpUnlockEvent()
        {
            IList<object> test = new List<object>
            {
                "00000000-0000-0000-0000-000000000001", "Barry", "BARRY", "Barry",
                "00000000-0000-0000-0000-000000000001", "Barry", "BARRY", "Barry", (uint) 7, "Barry", "BarryAuth",
                "BARRYPC",
                Guid.Parse("00000000-0000-0000-0000-000000000000"), "Barries", "Barry", 1024, 1, " BARRY.EXE",
                "10.80.6.1", 0,
                "Impersonation"
            };

            Assert.False(EventLogListener.IsNotValid(test));
        }

        /// <summary>
        ///     Ensure a type 7 (Unlock) logon with IpAddress="-" is filtered.
        ///     This is a local console unlock and is not of interest.
        /// </summary>
        [Fact]
        public void EvaluatesInvalidLocalConsoleUnlockEvent()
        {
            IList<object> test = new List<object>
            {
                "00000000-0000-0000-0000-000000000001", "Barry", "BARRY", "Barry",
                "00000000-0000-0000-0000-000000000001", "Barry", "BARRY", "Barry", (uint) 7, "Barry", "BarryAuth",
                "BARRYPC",
                Guid.Parse("00000000-0000-0000-0000-000000000000"), "Barries", "Barry", 1024, 1, " BARRY.EXE",
                "-", 0,
                "Impersonation"
            };

            Assert.True(EventLogListener.IsNotValid(test));
        }

        /// <summary>
        ///     Ensure invalid properties won't be passed
        /// </summary>
        [Fact]
        public void EvaluatesInvalidEvent()
        {
            IList<object> test = new List<object>
            {
                "00000000-0000-0000-0000-000000000001", "Barry", "BARRY", "Barry",
                "00000000-0000-0000-0000-000000000001", "Barry", "BARRY", "Barry", (uint) 2, "Barry", "BarryAuth",
                "BARRYPC",
                Guid.Parse("00000000-0000-0000-0000-000000000000"), "Barries", "Barry", 1024, 1, " BARRY.EXE", "-",
                1111,
                "All The Impersonation"
            };

            Assert.True(EventLogListener.IsNotValid(test));
        }

        /// <summary>
        ///     Ensure valid failure event properties will be passed (event 4625)
        /// </summary>
        [Fact]
        public void EvaluatesValidFailureEvent()
        {
            // 4625 property layout: SubjectUserSid[0], SubjectUserName[1], SubjectDomainName[2], SubjectLogonId[3],
            //   TargetUserSid[4], TargetUserName[5], TargetDomainName[6],
            //   Status[7], FailureReason[8], SubStatus[9],
            //   LogonType[10], LogonProcessName[11], AuthenticationPackageName[12], WorkstationName[13],
            //   TransmittedServices[14], LmPackageName[15], KeyLength[16],
            //   ProcessId[17], ProcessName[18], IpAddress[19], IpPort[20]
            IList<object> test = new List<object>
            {
                "00000000-0000-0000-0000-000000000001", "Barry", "BARRY", "Barry",
                "00000000-0000-0000-0000-000000000001", "Barry", "BARRY",
                "0xC000006D", "%%2313", "0xC000006A",
                (uint) 10, "Barry", "BarryAuth", "BARRYPC",
                "-", "-", 0,
                1, " BARRY.EXE", "192.168.1.100", 3389
            };

            Assert.False(EventLogListener.IsFailureNotValid(test));
        }

        /// <summary>
        ///     Ensure invalid failure event properties (non-interactive logon type) won't be passed (event 4625)
        /// </summary>
        [Fact]
        public void EvaluatesInvalidFailureEvent()
        {
            IList<object> test = new List<object>
            {
                "00000000-0000-0000-0000-000000000001", "Barry", "BARRY", "Barry",
                "00000000-0000-0000-0000-000000000001", "Barry", "BARRY",
                "0xC000006D", "%%2313", "0xC000006A",
                (uint) 3, "Barry", "BarryAuth", "BARRYPC",
                "-", "-", 0,
                1, " BARRY.EXE", "-", 0
            };

            Assert.True(EventLogListener.IsFailureNotValid(test));
        }

        /// <summary>
        ///     Ensure a valid 4634 logoff event (interactive type 10) is accepted
        /// </summary>
        [Fact]
        public void EvaluatesValidLogoffEvent()
        {
            // 4634 property layout: TargetUserSid[0], TargetUserName[1], TargetDomainName[2], TargetLogonId[3], LogonType[4]
            IList<object> test = new List<object>
            {
                "00000000-0000-0000-0000-000000000001", "Barry", "BARRY", "Barry", (uint) 10
            };

            Assert.False(EventLogListener.IsLogoffNotValid(test, false));
        }

        /// <summary>
        ///     Ensure an invalid 4634 logoff event (non-interactive logon type) is rejected
        /// </summary>
        [Fact]
        public void EvaluatesInvalidLogoffEvent()
        {
            IList<object> test = new List<object>
            {
                "00000000-0000-0000-0000-000000000001", "Barry", "BARRY", "Barry", (uint) 3
            };

            Assert.True(EventLogListener.IsLogoffNotValid(test, false));
        }

        /// <summary>
        ///     Ensure a 4647 user-initiated logoff event is always accepted (no LogonType field)
        /// </summary>
        [Fact]
        public void EvaluatesValidUserInitiatedLogoffEvent()
        {
            // 4647 property layout: TargetUserSid[0], TargetUserName[1], TargetDomainName[2], TargetLogonId[3]
            IList<object> test = new List<object>
            {
                "00000000-0000-0000-0000-000000000001", "Barry", "BARRY", "Barry"
            };

            Assert.False(EventLogListener.IsLogoffNotValid(test, true));
        }

        /// <summary>
        ///     Allow a single event to expire after 2 seconds
        /// </summary>
        [Fact]
        public void EventBagExpiresEvent()
        {
            var unused = new EventLogListener(2);
            EventLogListener.EventList.Add(1000);
            Assert.True(EventLogListener.EventList.Contains(1000));
            Thread.Sleep(3000);
            Assert.False(EventLogListener.EventList.Contains(1000));
        }

        /// <summary>
        ///     A longer test that ensures an event is kept while it is accessed
        /// </summary>
        [Fact]
        public void EventBagKeepsAccessedEvent()
        {
            var unused = new EventLogListener(2);
            var watch = new Stopwatch();
            watch.Start();

            EventLogListener.EventList.Add(1000);

            for (var i = 1; i < 2001; i++)
            {
                var count = EventLogListener.EventList.Count;
                if (i % 100 == 0)
                    _testOutputHelper.WriteLine(
                        $"Loop {i} @ {watch.ElapsedMilliseconds / 1000:N0} seconds, Bag Count: {count}");

                Assert.True(EventLogListener.EventList.Contains(1000));
                Thread.Sleep(10);
            }

            Thread.Sleep(3000);
            Assert.False(EventLogListener.EventList.Contains(1000));
        }

        /// <summary>
        ///     A long test (60 seconds) that allows us to observe cache population and expiry
        /// </summary>
        [Fact]
        public void EventBagPopulationAndExpiry()
        {
            var unused = new EventLogListener(2);
            var watch = new Stopwatch();
            watch.Start();
            var random = new Random();
            new Thread(delegate()
            {
                //Populate the cache for ~30 seconds so it will expire before the test has finished
                for (var i = 1; i < 1001; i++)
                {
                    EventLogListener.EventList.Add(random.Next(1000, 100000));
                    var tCount = EventLogListener.EventList.Count;
                    if (i % 20 == 0)
                        _testOutputHelper.WriteLine(
                            $"Thread loop {i} @ {watch.ElapsedMilliseconds} milliseconds, Bag Count: {tCount}");
                    Thread.Sleep(25);
                }
            }).Start();

            var hasExpired = false;
            for (var x = 1; x < 4001; x++)
            {
                Thread.Sleep(10);
                var count = EventLogListener.EventList.Count;
                if (x % 100 == 0)
                    _testOutputHelper.WriteLine(
                        $"Loop {x} @ {watch.ElapsedMilliseconds / 1000:N0} seconds, Bag Count: {count}");
                if (count == 0 && !hasExpired)
                {
                    _testOutputHelper.WriteLine($"Cache has emptied @ {watch.ElapsedMilliseconds / 1000:N0} seconds!");
                    hasExpired = true;
                }

                Assert.False(EventLogListener.EventList.Contains(999));
            }

            watch.Stop();
            Assert.True(hasExpired);
        }
    }
}