using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace OCPP.Core.Server
{
    /// <summary>
    /// Writes OCPP messages (in/out) into ONE file per day instead of one file per message
    /// and deletes dump files older than "MessageDumpRetentionDays" (default: 7 days)
    /// </summary>
    public static class MessageDumper
    {
        private static readonly object _lock = new object();
        private static DateTime _lastCleanup = DateTime.MinValue;

        public static void Dump(IConfiguration configuration, ILogger logger, string direction, string chargePointId, string message)
        {
            string dumpDir = configuration.GetValue<string>("MessageDumpDir");
            if (string.IsNullOrWhiteSpace(dumpDir)) return;

            DateTime now = DateTime.Now;
            string path = Path.Combine(dumpDir, string.Format("{0}_ocpp-messages.log", now.ToString("yyyy-MM-dd")));
            string line = string.Format("{0} | {1} | {2} | {3}{4}", now.ToString("yyyy-MM-dd HH:mm:ss.fff"), direction, chargePointId, message, Environment.NewLine);

            try
            {
                lock (_lock)
                {
                    Directory.CreateDirectory(dumpDir);
                    File.AppendAllText(path, line, Encoding.UTF8);

                    if (_lastCleanup.Date != now.Date)
                    {
                        _lastCleanup = now;
                        int retentionDays = configuration.GetValue<int>("MessageDumpRetentionDays", 7);
                        Task.Run(() => Cleanup(dumpDir, retentionDays, logger));
                    }
                }
            }
            catch (Exception exp)
            {
                logger.LogError(exp, "MessageDumper => Error dumping message to path: '{0}'", path);
            }
        }

        private static void Cleanup(string dumpDir, int retentionDays, ILogger logger)
        {
            if (retentionDays <= 0) return;

            DateTime limit = DateTime.Now.AddDays(-retentionDays);
            // "*_ocpp-messages.log" = current format / "*_ocpp??-in.txt" + "*_ocpp??-out.txt" = old format (one file per message)
            foreach (string pattern in new[] { "*_ocpp-messages.log", "*_ocpp??-in.txt", "*_ocpp??-out.txt" })
            {
                try
                {
                    foreach (string file in Directory.EnumerateFiles(dumpDir, pattern))
                    {
                        try
                        {
                            if (File.GetLastWriteTime(file) < limit)
                            {
                                File.Delete(file);
                            }
                        }
                        catch (Exception exp)
                        {
                            logger.LogWarning(exp, "MessageDumper => Error deleting old dump file '{0}'", file);
                        }
                    }
                }
                catch (Exception exp)
                {
                    logger.LogError(exp, "MessageDumper => Error cleaning up dump directory '{0}'", dumpDir);
                }
            }
        }
    }
}
