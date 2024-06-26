﻿using Convilguous_Shared;
using Convilguous_Shared_OSDependent;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Net.Mail;
using System.Runtime.Remoting.Lifetime;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MonitoringService
{
    public partial class Service1 : ServiceBase
    {
        GeneralFunctions GF = new GeneralFunctions();
        GeneralFunctionsAppSpecific GFS = new GeneralFunctionsAppSpecific();
        static string ServiceNaam = "MonitoringService";
        DateTime ControleerDoorsturenOp = DateTime.Now; // Wanneer volgende keer pas controleren op forwarding stilhangen ?
        SqlConnection SQLconnRemote;
        bool ExecutingMetingForwarded = false;
        int OpenConnecties = 0;
        bool OpenConnectiesGereageerd = false;

        bool CheckIncomingStarting = true;
        bool CheckForwardingStarting = true;
        DateTime CheckLastMailReceived = DateTime.UtcNow.AddDays(1);
        DateTime CheckLastMailForwarded = DateTime.UtcNow.AddDays(1);

        bool TestingOutgoingMail = false;
        bool TestingIncomingMail = false;


        public Service1()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            GeneralFunctions.ServiceName = ServiceNaam;
            bool StartupService = true;

            try
            {
                SQLconnRemote = new SqlConnection(@"server=database.spamfilter.be,14333;database=spamfilter;User ID=incoming;PWD=2rf32dfw;Asynchronous Processing=true;MultipleActiveResultSets=true");

                // Check if this is the database has been setup
                if (Environment.MachineName.ToLower() != "yoda")
                {
                    GeneralFunctionsAppSpecific.conn = new SqlConnection("server=localhost,14333;database=master;Integrated Security=SSPI");

                    if (GF.IntParse(GFS.SQL_SendQueryWithObjectResponse("IF EXISTS (SELECT Name FROM SysDatabases WHERE Name = 'spamfilter') BEGIN SELECT 1 END ELSE BEGIN SELECT 0 END")) == 0)
                    {
                        StartupService = false;
                        // Spamfilter does not exist, create the database in the default location, cannot be kille dby stopping the service !
                        new Thread(() => CreateDatabase()).Start();
                    }
                }
                if (StartupService)
                {
                    GeneralFunctionsAppSpecific.conn = new SqlConnection(@"server=localhost,14333;database=spamfilter;Integrated Security=SSPI;Asynchronous Processing=true;MultipleActiveResultSets=true");

                    new Thread(() => ControlesUitvoeren()) { IsBackground = true }.Start();
                }
            }
            catch (Exception eee)
            {
                GFS.LogError(eee, EventLogEntryType.FailureAudit, 2009282327, true);
                if (Environment.MachineName.ToLower() != "yoda") 
                    new Thread(() => TryStarting()) { IsBackground = true }.Start();
            }

            try
            {
                using (PowerShell powShell = PowerShell.Create())
                {
                    if (powShell.AddCommand("get-netfirewallrule").AddParameter("-DisplayName", "Spamfilter Sattelite SQL Server Connection").Invoke().Count == 0)
                    {
                        powShell.Commands.Clear();
                        powShell.AddScript("new-netfirewallrule -DisplayName \"Spamfilter Sattelite SQL Server Connection\" -Direction Inbound -LocalPort 14333 -Protocol TCP -Action Allow").Invoke();
                    }

                    if (powShell.AddCommand("get-netfirewallrule").AddParameter("-DisplayName", "Spamfilter Sattelite SMTP Inbound").Invoke().Count == 0)
                    {
                        powShell.Commands.Clear();
                        powShell.AddScript("new-netfirewallrule -DisplayName \"Spamfilter Sattelite SMTP Inbound\" -Direction Inbound -LocalPort 25 -Protocol TCP -Action Allow").Invoke();
                    }
                }
            }
            catch (Exception eee)
            {
                GFS.LogError(eee, EventLogEntryType.FailureAudit, 2101212207, true);
            }
        }

        private void TryStarting()
        {
            int Retries = 1;
            while (true)
            {
                Thread.Sleep(5000);
                try
                {
                    bool StartupService = true;

                    if (Environment.MachineName.ToLower() != "yoda")
                    {
                        if (GF.IntParse(GFS.SQL_SendQueryWithObjectResponse("IF EXISTS (SELECT Name FROM SysDatabases WHERE Name = 'spamfilter') BEGIN SELECT 1 END ELSE BEGIN SELECT 0 END")) == 0)
                        {
                            StartupService = false;
                            // Spamfilter does not exist, create the database in the default location, cannot be kille dby stopping the service !
                            new Thread(() => CreateDatabase()).Start();
                        }
                    }
                    if (StartupService)
                    {
                        GeneralFunctionsAppSpecific.conn = new SqlConnection(@"server=localhost,14333;database=spamfilter;Integrated Security=SSPI;Asynchronous Processing=true;MultipleActiveResultSets=true");

                        new Thread(() => ControlesUitvoeren()) { IsBackground = true }.Start();
                    }
                    break;
                }
                catch (Exception)
                {
                    GFS.LogError($"Re-trying the intial startup still fails, try #{Retries}", EventLogEntryType.Warning, 2101212138, true);
                }
                Retries++;
            }
        }

        private void CreateDatabase()
        {
            try
            {
                string Database = Path.GetPathRoot(Environment.SystemDirectory);
                string Logs = "";

                // Get drive with the name "Database"
                // And if available the one with "Logs"
                foreach (DriveInfo Drive in DriveInfo.GetDrives())
                {
                    try
                    {
                        if (Drive.VolumeLabel.ToLower() == "database")
                            Database = Drive.Name;
                        else if (Drive.VolumeLabel.ToLower() == "logs")
                            Logs = Drive.Name;
                    }
                    catch (Exception)
                    {
                    }
                }

                if (string.IsNullOrEmpty(Logs))
                    Logs = Database;

                if (!Directory.Exists(Path.Combine(Database, "Spamfilter")))
                    Directory.CreateDirectory(Path.Combine(Database, "Spamfilter"));
                if (!Directory.Exists(Path.Combine(Logs, "Spamfilter")))
                    Directory.CreateDirectory(Path.Combine(Logs, "Spamfilter"));

                // Create database
                GFS.SQL_SendQueryWithoutResponse($"CREATE DATABASE Spamfilter ON (NAME = 'Spamfilter', FILENAME = '{Database}\\Spamfilter\\Spamfilter_data.mdf') LOG ON (NAME = 'SpamfilterLog', FILENAME = '{Logs}\\Spamfilter\\Spamfilter_log.mdf')");
                GFS.SQL_SendQueryWithoutResponse($"CREATE DATABASE IPRanges ON (NAME = 'IPRanges', FILENAME = '{Database}\\Spamfilter\\IPRanges_data.mdf') LOG ON (NAME = 'IPRangesLog', FILENAME = '{Logs}\\Spamfilter\\IPRanges_log.mdf')");
                // Change recovery to simple
                GFS.SQL_SendQueryWithoutResponse("alter database Spamfilter set recovery simple");
                GFS.SQL_SendQueryWithoutResponse("alter database IPRanges set recovery simple");

                // switch to database Spamfitler
                GeneralFunctionsAppSpecific.conn.ChangeDatabase("Spamfilter");

                // Create the main tables
                // Get Offset from the maindatabase
                DataTable dtOffsets = GFS.SQL_SendWithDirectDataTableResponse(SQLconnRemote, "HaalMailIDOffSet");
                if (dtOffsets.Rows.Count > 0)
                {
                    int MailIDOffset = GF.IntParse(dtOffsets.Rows[0]["MailIDOffSet"]);
                    long SeedValue = GF.Int64Parse(dtOffsets.Rows[0]["SeedValue"]) + 65536;

                    if (SeedValue == 65536)
                    {
                        Random rndOffset = new Random();
                        SeedValue = (2000000 + MailIDOffset) + (long)rndOffset.Next(450000, 1230000) * 65536;
                    }

                    if (MailIDOffset == 0)
                    {
                        GFS.LogError("This server has no row in GeneralSettings table in the main database", EventLogEntryType.Error, 2010032237, true);
                    }
                    else if ((SeedValue - 2000000 - MailIDOffset) % 65536 != 0)
                    {
                        GFS.LogError($"Seedvalue {SeedValue} in GeneralSettings is not a valid value for this server with MailIDOffset {MailIDOffset}", EventLogEntryType.Error, 2010032238, true);
                    }
                    else
                    {
                        // Create Mail table
                        GFS.SQL_SendQueryWithoutResponse(
                            "CREATE TABLE [dbo].[Mail]( " +
                            $"    [ID] [bigint]  IDENTITY({SeedValue}, 65536) NOT NULL, " +
                            "    [MessageID] [bigint]  NOT NULL, " +
                            "    [MailFrom] [varchar] (255) NOT NULL, " +
                            "    [MailFromHost] [varchar] (255) NOT NULL, " +
                            "    [RcptTo] [varchar] (255) NOT NULL, " +
                            "    [RcptToHost] [varchar] (255) NOT NULL, " +
                            "    [Subject] [nvarchar] (255) NOT NULL default '', " +
                            "    [MessageSize] [bigint]  NOT NULL, " +
                            "    [MessageSizeSent] [bigint]  NOT NULL default 0, " +
                            "    [ServerName] [varchar] (255) NOT NULL, " +
                            "    [ServerIP] [varchar] (50) NOT NULL, " +
                            "    [ServerIPNum] [bigint]  NOT NULL, " +
                            "    [ErrorIncoming] [varchar] (255) NOT NULL, " +
                            "    [ErrorFilter] [varchar] (255) NOT NULL, " +
                            "    [ErrorForwarding] [varchar] (255) NOT NULL default '', " +
                            "    [ForwardingRetries] [int]  NOT NULL default 0, " +
                            "    [Status] [char] (5) NOT NULL, " +
                            "    [Datum] [datetime]  NOT NULL default CURRENT_TIMESTAMP, " +
                            "    [IncomingServer] [varchar] (50) NOT NULL default '127.0.0.1', " +
                            "    [ClientForward] [bit]  NOT NULL default 0, " +
                            "    [Checksum] [bigint]  NOT NULL default 0, " +
                            "    [PreChecked] [int]  NOT NULL default 0, " +
                            "    [XMailer] [varchar] (50) NOT NULL default '', " +
                            "    [XPriority] [varchar] (50) NOT NULL default '', " +
                            "    [XMSMailPriority] [varchar] (50) NOT NULL default '', " +
                            "    [XMimeOLE] [varchar] (50) NOT NULL default '', " +
                            "    [Busy] [int]  NOT NULL default 0, " +
                            "    [OriginatingHost] [varchar] (255) NOT NULL default '', " +
                            "    [Keywords] [nvarchar] (512) NOT NULL default '', " +
                            "    [LaatsteAktie] [datetime]  NOT NULL default CURRENT_TIMESTAMP, " +
                            "    [CommunicationsLog] [nvarchar] (max) NOT NULL default '', " +
                            "    [EIGHTBITMIME] [bit]  NOT NULL default 0, " +
                            "    [DateStartSending] [datetime]  NOT NULL default CURRENT_TIMESTAMP, " +
                            "    [UsingTLS] [bit]  NOT NULL default 0, " +
                            " CONSTRAINT [PK_Mail] PRIMARY KEY NONCLUSTERED " +
                            "( " +
                            "    [ID] ASC, " +
                            "    [MessageID] ASC " +
                            ") WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY] " +
                            ") ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TABLE [dbo].[BlockedByClients]( " +
                            "    [ID] [bigint] NOT NULL primary key, " +
                            "    [MailFrom] [varchar] (255) NOT NULL, " +
                            "    [RcptTo] [varchar] (255) NOT NULL, " +
                            "    [BlockStart] [datetime]  NOT NULL, " +
                            "    [BlockEnd] [datetime]  NOT NULL, " +
                            "    [InsertedBy] [varchar] (255) NOT NULL default CURRENT_USER)");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TABLE [dbo].[DeletedIPRanges]( " +
                            "	[ID] [bigint] IDENTITY(1,1) NOT NULL primary key, " +
                            "	[FirstIP] [bigint] NOT NULL, " +
                            "	[LastIP] [bigint] NOT NULL, " +
                            "	[DeletedID] [bigint] NOT NULL)");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TABLE [dbo].[FakeMailAddresses]( " +
                            "	[ID] [bigint] NOT NULL primary key, " +
                            "	[Email] [varchar](255) NOT NULL, " +
                            "	[ListedSince] [datetime] NOT NULL default CURRENT_TIMESTAMP)");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TABLE [dbo].[ForwardingSettings]( " +
                            "	[Domainname] [varchar](255) NOT NULL, " +
                            "	[Filter] [bit] NOT NULL, " +
                            "	[MX1] [varchar](255) NOT NULL, " +
                            "	[MX1Poort] [int] NOT NULL default 25, " +
                            "	[MX2] [varchar](255) NOT NULL, " +
                            "	[MX2Poort] [int] NOT NULL default 25, " +
                            "	[MX3] [varchar](255) NOT NULL, " +
                            "	[MX3Poort] [int] NOT NULL default 25, " +
                            "	[Beheerder] [varchar](40) NOT NULL, " +
                            "	[Vervaldag] [datetime] NOT NULL, " +
                            "	[OnlyGoodList] [bit] NOT NULL, " +
                            "	[MaxMessageSize] [bigint] NOT NULL default 20971520, " +
                            "	[AllowAbused] [bit] NOT NULL default 0)");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TABLE [dbo].[GoodMailAddresses]( " +
                            "	[ID] [bigint] NOT NULL primary key, " +
                            "	[Email] [varchar](255) NOT NULL, " +
                            "	[Beheerder] [varchar](40) NULL, " +
                            "	[ListedSince] [datetime] NOT NULL default CURRENT_TIMESTAMP)");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TABLE [dbo].[MailContent]( " +
                            "	[MessageID] [bigint] NOT NULL primary key, " +
                            "	[BodyBinary] [varbinary](max) NOT NULL, " +
                            "	[Datum] [datetime] NOT NULL default CURRENT_TIMESTAMP, " +
                            "	[Compressed] [bit] NOT NULL default 0) ");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TABLE [dbo].[MailForwarded]( " +
                            "	[ID] [bigint] IDENTITY(10000,1) NOT NULL primary key, " +
                            "	[MessageID] [bigint] NOT NULL, " +
                            "	[MailFrom] [varchar](255) NOT NULL, " +
                            "	[MailFromHost] [varchar](255) NOT NULL, " +
                            "	[RcptTo] [varchar](255) NOT NULL, " +
                            "	[RcptToHost] [varchar](255) NOT NULL, " +
                            "	[Subject] [nvarchar](255) NOT NULL default '', " +
                            "	[MessageSize] [bigint] NOT NULL, " +
                            "	[ServerName] [varchar](255) NOT NULL, " +
                            "	[ServerIP] [varchar](50) NOT NULL, " +
                            "	[ServerIPNum] [bigint] NOT NULL, " +
                            "	[Datum] [datetime] NOT NULL default CURRENT_TIMESTAMP, " +
                            "	[DatumDoorgestuurd] [datetime] NOT NULL, " +
                            "	[IncomingServer] [varchar](50) NOT NULL default '127.0.0.1', " +
                            "	[Status] [char](5) NOT NULL default '', " +
                            "	[Checksum] [bigint] NOT NULL default 0, " +
                            "	[XMailer] [varchar](50) NOT NULL default '', " +
                            "	[XPriority] [varchar](50) NOT NULL default '', " +
                            "	[XMSMailPriority] [varchar](50) NOT NULL default '', " +
                            "	[XMimeOLE] [varchar](50) NOT NULL default '', " +
                            "	[OriginatingHost] [varchar](255) NOT NULL default '', " +
                            "	[Keywords] [nvarchar](512) NOT NULL default '', " +
                            "	[CommunicationsLog] [nvarchar](max) NOT NULL default '', " +
                            "	[EIGHTBITMIME] [bit] NOT NULL default 0, " +
                            "	[UsingTLS] [bit] NOT NULL default 0)");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TABLE [dbo].[SubstituteEmails]( " +
                            "	[ID] [bigint] NOT NULL primary key, " +
                            "	[MailFrom] [varchar](255) NOT NULL, " +
                            "	[MailFromHost] [varchar](255) NOT NULL, " +
                            "	[RcptTo] [varchar](255) NOT NULL, " +
                            "	[RcptToHost] [varchar](255) NOT NULL, " +
                            "	[BeginDatum] [datetime] NOT NULL, " +
                            "	[EindDatum] [datetime] NOT NULL) ");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TABLE [dbo].[UndeliverableInTime]( " +
                            "	[ID] [bigint] IDENTITY(1,1) NOT NULL primary key, " +
                            "	[MessageID] [bigint] NOT NULL, " +
                            "	[RcptTo] [varchar](255) NOT NULL, " +
                            "	[Tijdstip] [datetime] NOT NULL default CURRENT_TIMESTAMP)");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TABLE [dbo].[UndeliverableSubjects]( " +
                            "	[ID] [bigint] NOT NULL, " +
                            "	[Subject] [nvarchar](1024) NOT NULL, " +
                            "	[MailFrom] [nvarchar](255) NOT NULL)");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TABLE [dbo].[UserPreferences]( " +
                            "	[ID] [bigint] NOT NULL, " +
                            "	[EmailAddress] [varchar](255) NOT NULL, " +
                            "	[NoNDRs] [bit] NOT NULL, " +
                            "	[ForwardFreeMails] [bit] NOT NULL)");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TABLE [dbo].[Performance]( " +
                            "	[IncomingStarting] [bit] NOT NULL," +
                            "	[ForwardingStarting] [bit] NOT NULL," +
                            "	[LastMailReceived] [datetime] NOT NULL," +
                            "	[LastMailForwarded] [datetime] NOT NULL," +
                            "	[IncomingProgress] [int] NOT NULL)");

                        GFS.SQL_SendQueryWithoutResponse("insert Performance(IncomingStarting, ForwardingStarting, LastMailForwarded, LastMailReceived, IncomingProgress) " +
                            "select 0,0,'19000101', '19000101', 0");

                        // Alle Types aanmaken

                        GFS.SQL_SendQueryWithoutResponse("CREATE TYPE BBCs AS TABLE( " +
                            "	[ID] [bigint] NULL, " +
                            "	[MailFrom] [nvarchar](max) NULL, " +
                            "	[RcptTo] [nvarchar](max) NULL, " +
                            "	[BlockStart] [datetime] NULL, " +
                            "	[BlockEnd] [datetime] NULL, " +
                            "	[InsertedBy] [varchar](max) NULL)");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TYPE ForwardingSettings AS TABLE( " +
                            "	[Domainname] [varchar](max) NULL, " +
                            "	[Filter] [bit] NOT NULL, " +
                            "	[MX1] [varchar](max) NOT NULL, " +
                            "	[MX1Poort] [int] NULL, " +
                            "	[MX2] [varchar](max) NOT NULL, " +
                            "	[MX2Poort] [int] NULL, " +
                            "	[MX3] [varchar](max) NOT NULL, " +
                            "	[MX3Poort] [int] NULL, " +
                            "	[Beheerder] [varchar](max) NOT NULL, " +
                            "	[Vervaldag] [datetime] NOT NULL, " +
                            "	[OnlyGoodList] [bit] NULL, " +
                            "	[MaxMessageSize] [bigint] NULL, " +
                            "	[AllowAbused] [bit] NULL )");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TYPE IDList AS TABLE( ID [bigint] NULL )");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TYPE IPRangesList AS TABLE( " +
                            "	[ID] [bigint] NOT NULL, " +
                            "	[FirstIP] [bigint] NOT NULL, " +
                            "	[LastIP] [bigint] NOT NULL, " +
                            "	[Blocked] [bit] NOT NULL, " +
                            "	[DateBlocked] [datetime] NOT NULL, " +
                            "	[Description] [varchar](max) NOT NULL, " +
                            "	[LastUpdater] [varchar](max) NOT NULL, " +
                            "	[ListToProcess] [bigint] NOT NULL, " +
                            "	[FirstMessageID] [bigint] NOT NULL, " +
                            "	[Corrected] [bit] NOT NULL, " +
                            "	[Abused] [bit] NULL) ");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TYPE MailAddresses AS TABLE( " +
                            "	[ID] [bigint] NULL, " +
                            "	[Email] [varchar](max) NULL, " +
                            "	[Beheerder] [varchar](max) NULL, " +
                            "	[ListedSince] [datetime] NULL) ");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TYPE MessageIDList AS TABLE( MessageID bigint NULL)");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TYPE NDRs AS TABLE( " +
                            "	[ID] [bigint] NULL, " +
                            "	[Subject] [nvarchar](max) NULL, " +
                            "	[MailFrom] [nvarchar](max) NULL) ");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TYPE STEs AS TABLE( " +
                            "	[ID] [bigint] NULL, " +
                            "	[MailFrom] [varchar](max) NULL, " +
                            "	[MailFromHost] [varchar](max) NULL, " +
                            "	[RcptTo] [varchar](max) NULL, " +
                            "	[RcptToHost] [varchar](max) NULL, " +
                            "	[BeginDatum] [datetime] NULL, " +
                            "	[EindDatum] [datetime] NULL)");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TYPE UserPrefs AS TABLE( " +
                            "	[ID] [bigint] NULL, " +
                            "	[EmailAddress] [varchar](max) NULL, " +
                            "	[NoNDRs] [bit] NULL, " +
                            "	[ForwardFreeMails] [bit] NULL)");

                        GeneralFunctionsAppSpecific.conn.ChangeDatabase("IPRanges");

                        GFS.SQL_SendQueryWithoutResponse("CREATE TABLE IPRanges( " +
                            "	[ID] [bigint] NOT NULL primary key, " +
                            "	[FirstIP] [bigint] NOT NULL, " +
                            "	[LastIP] [bigint] NOT NULL, " +
                            "	[Blocked] [bit] NOT NULL, " +
                            "	[DateBlocked] [datetime] NOT NULL default CURRENT_TIMESTAMP, " +
                            "	[Description] [varchar](100) NOT NULL default '', " +
                            "	[LastUpdater] [varchar](50) NOT NULL default CURRENT_USER, " +
                            "	[ListToProcess] [bigint] NOT NULL default 0, " +
                            "	[FirstMessageID] [bigint] NOT NULL default 0, " +
                            "	[Corrected] [bit] NOT NULL default 0, " +
                            "	[Abused] [bit] NOT NULL default 0) ");


                        GeneralFunctionsAppSpecific.conn.ChangeDatabase("Spamfilter");

                        // Stored Procedures aanmaken

                        GFS.SQL_SendQueryWithoutResponse("create PROCEDURE BerichtVerstuurd @ID bigint, @CommunicationsLog nvarchar(max) AS " +
                            " " +
                            "BEGIN TRAN  " +
                            " " +
                            "INSERT MailForwarded(MessageID, MailFrom, MailFromHost, RcptTo, RcptToHost, MessageSize, [Subject], [Status], ServerName, ServerIP,  " +
                            "ServerIPNum, Datum, DatumDoorgestuurd, IncomingServer,[Checksum], XMailer, XPriority, XMSMailPriority, XMimeOLE, OriginatingHost,  " +
                            "EIGHTBITMIME, CommunicationsLog, UsingTLS)  " +
                            "SELECT MessageID, MailFrom, MailFromHost, RcptTo, RcptToHost, MessageSize, [Subject], [Status] , ServerName, ServerIP,  " +
                            "ServerIPNum, Datum, CURRENT_TIMESTAMP, IncomingServer,[Checksum], XMailer, XPriority, XMSMailPriority, XMimeOLE, OriginatingHost,  " +
                            "EIGHTBITMIME, CommunicationsLog + @CommunicationsLog, UsingTLS  " +
                            "FROM Mail  " +
                            "WHERE ID = @ID  " +
                            " " +
                            "if @@error <> 0  " +
                            "begin " +
                            "rollback tran  " +
                            "return  " +
                            "end  " +
                            " " +
                            "DELETE FROM Mail WHERE ID = @ID  " +
                            " " +
                            "if @@error <> 0  " +
                            "begin " +
                            "rollback tran  " +
                            "return  " +
                            "end  " +
                            " " +
                            "update Performance " +
                            "set LastMailForwarded = GETUTCDATE() " +
                            " " +
                            "if @@error <> 0  " +
                            "begin " +
                            "rollback tran  " +
                            "return  " +
                            "end  " +
                            " " +
                            "COMMIT TRAN");

                        GFS.SQL_SendQueryWithoutResponse("CREATE PROCEDURE BezigMetMail @ID bigint AS " +
                            " " +
                            "declare @Nu datetime = CURRENT_TIMESTAMP " +
                            "declare @RcptToHost varchar(255) " +
                            " " +
                            "select @RcptToHost = isnull(SE.RcptToHost, M.RcptToHost) " +
                            "from Mail M  " +
                            "left outer join SubstituteEmails SE on SE.MailFrom = M.RcptTo and SE.BeginDatum <= @Nu and SE.EindDatum >= @Nu " +
                            "where M.ID = @ID " +
                            " " +
                            "update M " +
                            "set DateStartSending = @Nu " +
                            "from Mail M  " +
                            "left outer join SubstituteEmails SE on SE.MailFrom = M.RcptTo and SE.BeginDatum <= @Nu and SE.EindDatum >= @Nu " +
                            "where isnull(SE.RcptToHost, M.RcptToHost) = @RcptToHost " +
                            "and M.Busy = 1");

                        GFS.SQL_SendQueryWithoutResponse("create procedure BlockedByClientsSync @BlockedByClients as BBCs readonly as " +
                            " " +
                            "insert BlockedByClients(ID, MailFrom, RcptTo, BlockStart, BlockEnd, InsertedBy) " +
                            "select S.ID, S.MailFrom, S.RcptTo, S.BlockStart, S.BlockEnd, S.InsertedBy " +
                            "from @BlockedByClients S " +
                            "left outer join BlockedByClients T on T.ID = S.ID " +
                            "where isnull(T.ID, 0) = 0 " +
                            " " +
                            "delete T " +
                            "from BlockedByClients T " +
                            "left outer join @BlockedByClients S on T.ID = S.ID " +
                            "where isnull(S.ID, 0) = 0");

                        GFS.SQL_SendQueryWithoutResponse("create procedure FakeMailAddressesAddBulk @FakeMailAddressesList as MailAddresses readonly as " +
                            " " +
                            "insert FakeMailAddresses(ID, Email, ListedSince) " +
                            "select ID, Email, ListedSince " +
                            "from @FakeMailAddressesList");

                        GFS.SQL_SendQueryWithoutResponse("create procedure FakeMailAddressesDeleteBulk @IDs as IDList readonly as " +
                            " " +
                            "delete M " +
                            "from FakeMailAddresses M " +
                            "inner join @IDs S on M.ID = S.ID");

                        GFS.SQL_SendQueryWithoutResponse("create procedure FakeMailAddressesGetMaxID as " +
                            " " +
                            "select max(ID) as ID from FakeMailAddresses");

                        GFS.SQL_SendQueryWithoutResponse("create procedure ForwardingSettingsSync @ForwardingSettings as ForwardingSettings readonly as " +
                            " " +
                            "update T " +
                            "set [Filter] = S.[Filter], MX1 = S.MX1, MX1Poort = S.MX1Poort,  " +
                            "   MX2 = S.MX2, MX2Poort = S.MX2Poort, " +
                            "   MX3 = S.MX3, MX3Poort = S.MX3Poort,  " +
                            "   Beheerder = S.Beheerder, VervalDag = S.Vervaldag,  " +
                            "   OnlyGoodList = S.OnlyGoodList, MaxMessageSize = S.MaxMessageSize, AllowAbused = S.AllowAbused " +
                            "from ForwardingSettings T " +
                            "inner join @ForwardingSettings S on T.Domainname = S.Domainname collate SQL_Latin1_General_CP1_CI_AS " +
                            "where T.[Filter] <> S.[Filter] or T.MX1 <> S.MX1 collate SQL_Latin1_General_CP1_CI_AS or T.MX1Poort <> S.MX1Poort or  " +
                            "   T.MX2 <> S.MX2 collate SQL_Latin1_General_CP1_CI_AS or T.MX2Poort <> S.MX2Poort or " +
                            "   T.MX3 <> S.MX3 collate SQL_Latin1_General_CP1_CI_AS or T.MX3Poort <> S.MX3Poort or  " +
                            "   T.Beheerder <> S.Beheerder collate SQL_Latin1_General_CP1_CI_AS or T.VervalDag <> S.Vervaldag or " +
                            "   T.OnlyGoodList <> S.OnlyGoodList or T.MaxMessageSize <> S.MaxMessageSize or T.AllowAbused <> S.AllowAbused " +
                            " " +
                            "insert ForwardingSettings(Domainname, MX1, MX1Poort, MX2, MX2Poort, MX3, MX3Poort, Beheerder, Vervaldag, OnlyGoodList, [Filter], MaxMessageSize, AllowAbused) " +
                            "select S.Domainname, S.MX1, S.MX1Poort, S.MX2, S.MX2Poort, S.MX3, S.MX3Poort, S.Beheerder, S.Vervaldag, S.OnlyGoodList, S.[Filter], S.MaxMessageSize, S.AllowAbused " +
                            "from @ForwardingSettings S " +
                            "left outer join ForwardingSettings T on T.Domainname = S.Domainname collate SQL_Latin1_General_CP1_CI_AS " +
                            "where T.Domainname is null ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure GetMXRecords @RcptToHost varchar(255) AS " +
                            " " +
                            "declare @MXrecords as table( " +
                            "	MXRecord varchar(255), " +
                            "	[Port]	int " +
                            ") " +
                            " " +
                            "insert @MXRecords(MXRecord, [Port]) " +
                            "select MX1, MX1Poort " +
                            "from ForwardingSettings  " +
                            "where Domainname = @RcptToHost " +
                            " " +
                            "if exists (select Domainname from ForwardingSettings where Domainname = @RcptToHost and MX2 <> '') " +
                            "begin " +
                            "	insert @MXRecords(MXRecord, [Port]) " +
                            "	select MX2, MX2Poort " +
                            "	from ForwardingSettings  " +
                            "	where Domainname = @RcptToHost " +
                            "end " +
                            "if exists (select Domainname from ForwardingSettings where Domainname = @RcptToHost and MX3 <> '') " +
                            "begin " +
                            "	insert @MXRecords(MXRecord, [Port]) " +
                            "	select MX3, MX3Poort " +
                            "	from ForwardingSettings  " +
                            "	where Domainname = @RcptToHost " +
                            "end " +
                            " " +
                            "if not exists (select MXRecord from @MXRecords) " +
                            "begin " +
                            "	insert @MXRecords(MXRecord, [Port]) " +
                            "	select 'relay.iwwerall.lu', 25 " +
                            "end " +
                            " " +
                            "select MXRecord, [Port] " +
                            "from @MXRecords");

                        GFS.SQL_SendQueryWithoutResponse("create procedure GoodMailAddressesAddBulk @GoodMailAddressesList as MailAddresses readonly as " +
                            " " +
                            "insert GoodMailAddresses(ID, Email, Beheerder, ListedSince) " +
                            "select ID, Email, Beheerder, ListedSince " +
                            "from @GoodMailAddressesList ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure GoodMailAddressesDeleteBulk @IDs as IDList readonly as " +
                            " " +
                            "delete M " +
                            "from GoodMailAddresses M " +
                            "inner join @IDs S on M.ID = S.ID ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure GoodMailAddressesGetMaxID as " +
                            " " +
                            "select max(ID) as ID from GoodMailAddresses");

                        GFS.SQL_SendQueryWithoutResponse("create procedure HaalControleMetingen as " +
                            " " +
                            "declare @Metingen as table( " +
                            "	Waarde	bigint,  " +
                            "	Beschrijving 	char(20)) " +
                            "	 " +
                            "insert @Metingen(Waarde, Beschrijving)  " +
                            "select DATEDIFF(day,MIN(Datum),CURRENT_TIMESTAMP),'OldestMail'  " +
                            "from Mail  " +
                            " " +
                            "insert @Metingen(Waarde, Beschrijving)  " +
                            "select DATEDIFF(day,MIN(Datum),CURRENT_TIMESTAMP),'OldestForwardedMail'  " +
                            "from MailForwarded  " +
                            " " +
                            "insert @Metingen(Waarde, Beschrijving)  " +
                            "select COUNT(*),'IPRangesTotal'  " +
                            "from IPRanges.dbo.IPRanges  " +
                            " " +
                            "insert @Metingen(Waarde, Beschrijving)  " +
                            "select COUNT(*),'IPRangesBlocked'  " +
                            "from IPRanges.dbo.IPRanges  " +
                            "where Blocked = 1 " +
                            "group by Blocked " +
                            " " +
                            "insert @Metingen(Waarde, Beschrijving)  " +
                            "select COUNT(*),'IPRangesCleared'  " +
                            "from IPRanges.dbo.IPRanges  " +
                            "where Blocked = 0 " +
                            "group by blocked " +
                            " " +
                            "insert @Metingen(Waarde, Beschrijving)  " +
                            "select COUNT(*),'MailWaiting' " +
                            "from Mail  " +
                            " " +
                            "insert @Metingen(Waarde, Beschrijving)  " +
                            "select COUNT(*),'MailForwarded'  " +
                            "from MailForwarded  " +
                            " " +
                            "insert @Metingen(Waarde, Beschrijving)  " +
                            "select COUNT(*), 'MailAllowed' " +
                            "from Mail M, ForwardingSettings F  " +
                            "WHERE (M.[Status] = ''  " +
                            "AND M.MessageID <> 0  " +
                            "AND F.Domainname = M.RcptToHost  " +
                            "AND F.[Filter] = 1  " +
                            "AND M.ForwardingRetries < 10  " +
                            "AND M.MessageSize <> 0  " +
                            "AND [Status] <> 'SIZE'  " +
                            "AND PreChecked = 10 )  " +
                            "OR ( M.[Status] <> 'RECV'  " +
                            "AND M.[Status] <> 'FAIL'  " +
                            "AND M.[Status] <> 'RSET'  " +
                            "AND M.[Status] <> 'SIZE'  " +
                            "AND M.MessageID <> 0  " +
                            "AND F.Domainname = M.RcptToHost  " +
                            "AND F.[Filter] = 0  " +
                            "AND M.ForwardingRetries < 10  " +
                            "AND M.MessageSize <> 0 )  " +
                            " " +
                            "select Waarde,Beschrijving  " +
                            "from @Metingen  ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure HaalVolgendeGoedeMail AS " +
                            " " +
                            "declare @MaxMessageSize bigint = 52428800 " +
                            "DECLARE @Domainname varchar(255) " +
                            "declare @AantalMails int " +
                            "declare @BlockSize int = 10240 " +
                            " " +
                            "IF NOT EXISTS (SELECT ID FROM MAIL WHERE Busy = 1)  " +
                            "BEGIN " +
                            "	select top 1 M.ID, lower(M.RcptTo) as RcptTo, lower(M.MailFrom) as MailFrom, C.BodyBinary, isnull(F.MX1,'mail.seerz.com') as MX1, isnull(F.MX1Poort,25) as MX1Poort,  " +
                            "		M.MessageSize, M.MessageID, M.EIGHTBITMIME, M.ErrorForwarding, M.ForwardingRetries, M.Datum, 0 as Volgorde, @BlockSize as [BlockSize] " +
                            "	FROM Mail M  " +
                            "	LEFT OUTER JOIN ForwardingSettings F ON F.Domainname = M.RcptToHost, MailContent C " +
                            "	WHERE ((M.Status = '' AND F.Filter = 1 AND M.PreChecked = 10) " +
                            "	OR ( M.Status <> 'RECV' AND M.Status <> 'FAIL' AND Status <> 'SIZE' AND F.Filter = 0 ))      " +
                            "	AND M.MessageID <> 0   " +
                            "	AND F.Domainname = M.RcptToHost      " +
                            "	AND DATEADD(mi,M.ForwardingRetries*10,M.Datum) < CURRENT_TIMESTAMP      " +
                            "	AND M.Busy = 0  " +
                            "	AND M.ForwardingRetries < 10  " +
                            "	AND M.MessageSize <> 0      " +
                            "	AND M.MessageSize <= @MaxMessageSize " +
                            "	AND C.MessageID = M.MessageID      " +
                            "	AND M.RcptTo not in (select MailFrom from SubstituteEmails where BeginDatum <= CURRENT_TIMESTAMP and EindDatum >= CURRENT_TIMESTAMP) " +
                            " " +
                            "	union all  " +
                            " " +
                            "	select top 1 M.ID, lower(S.RcptTo) as RcptTo, lower(M.MailFrom) as MailFrom, C.BodyBinary, isnull(X.MX1,'relay.iwwerall.lu') as MX1, isnull(X.MX1Poort,25) as MX1Poort,  " +
                            "		M.MessageSize, M.MessageID, M.EIGHTBITMIME, M.ErrorForwarding, M.ForwardingRetries, M.Datum, 1 as Volgorde, @BlockSize as [BlockSize] " +
                            "	FROM Mail M  " +
                            "	LEFT OUTER JOIN ForwardingSettings F ON F.Domainname = M.RcptToHost, SubstituteEmails S  " +
                            "	LEFT OUTER JOIN ForwardingSettings X ON X.Domainname = S.RcptToHost, MailContent C " +
                            "	WHERE ((M.Status = '' AND F.Filter = 1 AND M.PreChecked = 10) " +
                            "	OR ( M.Status <> 'RECV' AND M.Status <> 'FAIL' AND Status <> 'SIZE' AND F.Filter = 0 ))      " +
                            "	AND M.MessageID <> 0   " +
                            "	AND DATEADD(mi,M.ForwardingRetries*10,M.Datum) < CURRENT_TIMESTAMP      " +
                            "	AND M.Busy = 0  " +
                            "	AND M.ForwardingRetries < 10  " +
                            "	AND M.MessageSize <> 0      " +
                            "	AND M.MessageSize <= @MaxMessageSize " +
                            "	AND C.MessageID = M.MessageID      " +
                            "	AND S.MailFrom = M.RcptTo " +
                            "	AND S.MailFromHost = M.RcptToHost " +
                            "	AND S.BeginDatum <= CURRENT_TIMESTAMP " +
                            "	AND S.EindDatum >= CURRENT_TIMESTAMP " +
                            "	ORDER BY Volgorde, M.ForwardingRetries, M.Datum " +
                            "END");

                        GFS.SQL_SendQueryWithoutResponse("create procedure HaalVolgendeGoedeMailDomain AS " +
                            " " +
                            "declare @Nu datetime = CURRENT_TIMESTAMP " +
                            " " +
                            "SELECT isnull(M.RcptToHost, SE.RcptToHost) as RcptToHost, count(*) as Aantal " +
                            "FROM Mail M  " +
                            "left outer join ForwardingSettings F ON F.Domainname = M.RcptToHost " +
                            "left outer join SubstituteEmails SE on SE.MailFrom = M.RcptTo and SE.BeginDatum <= @Nu and SE.EindDatum >= @Nu " +
                            "left outer join Mail MM on MM.RcpttoHost = isnull(M.RcptToHost, SE.RcptToHost) and MM.Busy = 1 " +
                            "WHERE ((M.[Status] = '' AND isnull(F.Filter,1) = 1 AND M.PreChecked = 10) " +
                            "	OR ( M.[Status] <> 'RECV' AND M.[Status] <> 'FAIL' AND M.[Status] <> 'SIZE' AND isnull(F.Filter,0) = 0 ))  " +
                            "and M.ForwardingRetries < 10 " +
                            "AND M.MessageSize <> 0 " +
                            "AND M.MessageSize <= F.MaxMessageSize " +
                            "AND DATEADD(mi,M.ForwardingRetries*10,M.Datum) < CURRENT_TIMESTAMP " +
                            "AND M.Busy = 0 " +
                            "AND M.MessageID <> 0   " +
                            "and isnull(MM.ID, 0) = 0 " +
                            "group by M.RcptToHost, SE.RcptToHost " +
                            " " +
                            "update Performance set ForwardingStarting = 0");

                        GFS.SQL_SendQueryWithoutResponse("create procedure HaalVolgendeGoedeMailDomainLijst @RcptToHost varchar(255) AS " +
                            " " +
                            "declare @Nu datetime = CURRENT_TIMESTAMP " +
                            " " +
                            "select M.ID, lower(isnull(SE.RcptTo, M.RcptTo)) as RcptTo, lower(M.MailFrom) as MailFrom, C.BodyBinary, M.MessageSize, M.MessageID,  " +
                            "	M.ErrorForwarding, M.ForwardingRetries, M.Datum, isnull(SE.RcptToHost, M.RcptToHost) as RcptToHost " +
                            "from Mail M  " +
                            "inner join MailContent C on C.MessageID = M.MessageID " +
                            "left outer join ForwardingSettings F ON F.Domainname = M.RcptToHost " +
                            "left outer join SubstituteEmails SE on SE.MailFrom = M.RcptTo and SE.BeginDatum <= @Nu and SE.EindDatum >= @Nu " +
                            "where ((M.Status = '' AND isnull(F.Filter,1) = 1 AND M.PreChecked = 10) " +
                            "	OR ( M.Status <> 'RECV' AND M.Status <> 'FAIL' AND Status <> 'SIZE' AND isnull(F.Filter,0) = 0 ))  " +
                            "and M.ForwardingRetries < 10 " +
                            "and M.MessageSize <> 0 " +
                            "and M.MessageSize <= F.MaxMessageSize " +
                            "and DATEADD(mi,M.ForwardingRetries*10,M.Datum) < @Nu " +
                            "and M.Busy = 0 " +
                            "and isnull(SE.RcptToHost, M.RcptToHost) = @RcptToHost " +
                            "AND M.MessageID <> 0   " +
                            "  " +
                            "update M " +
                            "set Busy = 1, ForwardingRetries = ForwardingRetries + 1, DateStartSending = @Nu " +
                            "from Mail M  " +
                            "left outer join ForwardingSettings F ON F.Domainname = M.RcptToHost " +
                            "left outer join SubstituteEmails SE on SE.MailFrom = M.RcptTo and SE.BeginDatum <= @Nu and SE.EindDatum >= @Nu " +
                            "where ((M.Status = '' AND isnull(F.Filter,1) = 1 AND M.PreChecked = 10) " +
                            "	OR ( M.Status <> 'RECV' AND M.Status <> 'FAIL' AND Status <> 'SIZE' AND isnull(F.Filter,0) = 0 ))  " +
                            "and M.ForwardingRetries < 10 " +
                            "and M.MessageSize <> 0 " +
                            "and M.MessageSize <= F.MaxMessageSize " +
                            "and DATEADD(mi,M.ForwardingRetries*10,M.Datum) < @Nu " +
                            "and M.Busy = 0 " +
                            "and isnull(SE.RcptToHost, M.RcptToHost) = @RcptToHost " +
                            "AND M.MessageID <> 0");

                        GFS.SQL_SendQueryWithoutResponse("create procedure IPRangesAddBulk @IPRangesList as IPRangesList readonly as " +
                            "  " +
                            "insert IPRanges.dbo.IPRanges (ID, FirstIP, LastIP, Blocked, DateBlocked, [Description], LastUpdater, ListToProcess, FirstMessageID, Corrected, Abused) " +
                            "select ID, FirstIP, LastIP, Blocked, DateBlocked, [Description], LastUpdater, ListToProcess, FirstMessageID, Corrected, Abused " +
                            "from @IPRangesList ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure IPRangesDeleteBulk @IDs as IDList readonly as " +
                            " " +
                            "insert DeletedIPRanges(FirstIP, LastIP, DeletedID) " +
                            "select IP.FirstIP, IP.LastIP, IP.ID " +
                            "from IPRanges.dbo.IPRanges IP " +
                            "inner join @IDs S on IP.ID = S.ID " +
                            " " +
                            "delete IP " +
                            "from IPRanges.dbo.IPRanges IP " +
                            "inner join @IDs S on IP.ID = S.ID ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure IPRangesGetMaxID as " +
                            " " +
                            "select max(ID) as ID from IPRanges.dbo.IPRanges ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure IsCustomerOnlyGoodListActive @ID bigint as " +
                            " " +
                            "IF EXISTS (SELECT * FROM ForwardingSettings WHERE OnlyGoodList = 1  " +
                            "	AND Domainname IN (SELECT RcptToHost FROM Mail WHERE MessageID = @ID))  " +
                            "BEGIN  " +
                            "	SELECT 'JA'  " +
                            "END  " +
                            "ELSE  " +
                            "BEGIN  " +
                            "	SELECT 'NEEN'  " +
                            "END ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure IsDomeinGeabbonneerd @ID bigint as " +
                            " " +
                            "IF EXISTS (SELECT * FROM ForwardingSettings WHERE Domainname IN  " +
                            "	(SELECT RcptToHost FROM Mail WHERE MessageID = @ID) AND Filter = 1)  " +
                            "BEGIN  " +
                            "	SELECT 'JA'  " +
                            "END  " +
                            "ELSE  " +
                            "BEGIN  " +
                            "	SELECT 'NEEN'  " +
                            "END ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure IsMailUndeliverable @ID bigint as " +
                            "" +
                            "if not exists (select U.ID from UserPreferences U, Mail M " +
                            "	where U.EmailAddress = M.RcptTo   " +
                            "	and U.NoNDRs = 0 and MessageID = @ID) " +
                            "begin " +
                            "	if exists (select U.ID from UndeliverableSubjects U, Mail M " +
                            "		where M.Subject like U.Subject ESCAPE '['          " +
                            "		and M.MailFrom like U.MailFrom ESCAPE '['          " +
                            "		and MessageID = @ID " +
                            "		and M.RcptToHost in (select DomainName from ForwardingSettings where filter = 1))      " +
                            "	begin      /* Opslaan dat er een undeliverable is geweest */       " +
                            "		declare @RcptTo varchar(255)       " +
                            "		declare @Retries int        " +
                            "	 " +
                            "		select @RcptTo = RcptTo, @Retries = ForwardingRetries  " +
                            "		from Mail where MessageID = @ID             " +
                            "	 " +
                            "		if (@Retries = 0)       " +
                            "		begin " +
                            "			insert UndeliverableInTime (RcptTo, MessageID)  " +
                            "			values (@RcptTo, @ID) " +
                            "		end  " +
                            "	 " +
                            "		if exists (select count(*) from UndeliverableInTime where RcptTo = @RcptTo group by messageid having count(*) > 5) " +
                            "		begin " +
                            "			select 'JA' " +
                            "		end  " +
                            "		else  " +
                            "		begin " +
                            "			select 'NEEN' " +
                            "		end " +
                            "	end " +
                            "	else  " +
                            "	begin " +
                            "		select 'NEEN' " +
                            "	end " +
                            "end " +
                            "else  " +
                            "begin " +
                            "	select 'NEEN' " +
                            "end ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure IsRcptToHostGeldig @RcptToHost varchar(255) as " +
                            " " +
                            "IF EXISTS (SELECT * FROM ForwardingSettings WHERE Domainname = @RcptToHost) " +
                            "BEGIN " +
                            "	SELECT 'JA'  " +
                            "END  " +
                            "ELSE " +
                            "BEGIN  " +
                            "	SELECT 'NEEN'  " +
                            "END ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure IsRecipientFake @ID bigint as " +
                            " " +
                            "IF EXISTS (SELECT * FROM FakeMailAddresses WHERE Email IN (SELECT RcptTo FROM Mail WHERE MessageID = @ID)) " +
                            "BEGIN " +
                            "	SELECT 'JA'  " +
                            "END " +
                            "ELSE " +
                            "BEGIN  " +
                            "SELECT 'NEEN' " +
                            "END ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure IsRecipientGood @ID bigint as " +
                            " " +
                            "IF EXISTS (SELECT * FROM GoodMailAddresses WHERE Email IN (SELECT RcptTo FROM Mail WHERE MessageID = @ID)) " +
                            "BEGIN  " +
                            "	SELECT 'JA'  " +
                            "END " +
                            "ELSE  " +
                            "BEGIN  " +
                            "	SELECT 'NEEN' " +
                            "END ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure IsSenderBlockedByClient @ID bigint as " +
                            " " +
                            "IF EXISTS (SELECT * FROM BlockedByClients B, Mail M  " +
                            "	WHERE M.RcptTo = B.RcptTo AND B.MailFrom = M.MailFrom AND M.MessageID = @ID  " +
                            "	AND BlockStart <= CURRENT_TIMESTAMP AND BlockEnd >= CURRENT_TIMESTAMP )  " +
                            "BEGIN " +
                            "	SELECT 'JA'  " +
                            "END " +
                            "ELSE  " +
                            "BEGIN " +
                            "	SELECT 'NEEN' " +
                            "END ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MailAllowedDeleteBulk @IDs as IDList readonly as " +
                            " " +
                            "delete T " +
                            "from Mail T " +
                            "inner join @IDs S on T.ID = S.ID ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MailAllowedGetAll as " +
                            " " +
                            "declare @Vanaf datetime  " +
                            " " +
                            "select @Vanaf = dateadd(minute, -5, CURRENT_TIMESTAMP) " +
                            " " +
                            "SELECT M.MessageID, M.MailFrom, M.MailFromHost, M.RcptTo, M.RcptToHost, M.MessageSize, M.ServerName, M.[Subject], M.ServerIP, M.ServerIPNum, M.Datum,  " +
                            "	M.[Status] as Reason, M.IncomingServer, M.[Checksum], M.XMailer, M.XPriority, M.XMSMailPriority, M.XMimeOLE, M.OriginatingHost, M.CommunicationsLog,  " +
                            "	M.Keywords, M.ErrorIncoming, M.ErrorFilter, M.ErrorForwarding, M.ForwardingRetries, M.ClientForward, 1 as Importing, ID as ImportingID " +
                            "FROM Mail  M " +
                            "inner join ForwardingSettings F on F.Domainname = M.RcptToHost and F.Filter = 1 " +
                            "WHERE ((M.[Status] = '' AND F.Filter = 1 AND PreChecked = 10 )  " +
                            "	OR (M.[Status] <> 'RECV' AND M.[Status] <> 'FAIL' AND M.[Status] <> 'RSET' AND M.[Status] <> 'SIZE' AND F.Filter = 0))   " +
                            "and M.MessageSize <> 0 " +
                            "and M.MessageID <> 0 " +
                            "AND Datum < @Vanaf " +
                            "AND Busy = 0  ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MailBlockedDeleteBulk @IDs as IDList readonly as " +
                            " " +
                            "delete T " +
                            "from Mail T " +
                            "inner join @IDs S on T.ID = S.ID ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MailBlockedGetAll as " +
                            " " +
                            "select 	M.[MessageID], M.[MailFrom], M.[MailFromHost], M.[RcptTo], M.[RcptToHost], M.[MessageSize], M.[ServerName], M.[Subject], M.[ServerIP], M.[ServerIPNum], M.[Datum],  " +
                            "	M.[Status] as  [Reason], M.[IncomingServer], M.[CheckSum], M.[XMailer], M.[XPriority], M.[XMSMailPriority], M.[XMimeOLE], M.[OriginatingHost], M.[CommunicationsLog], " +
                            "	1 as [Importing], M.ID as [ImportingID] " +
                            "from Mail M " +
                            "inner join ForwardingSettings F on F.Domainname = M.RcptToHost and F.Filter = 1 " +
                            "WHERE ((PreChecked = 11 AND MessageSize <> 0 AND Status <> 'RECV')  " +
                            "or Status = 'FAIL' " +
                            "	or ((Status = 'BLOCK' OR Status = 'FAIL' OR Status = 'SIZE' ) AND PreChecked <> 11)) " +
                            "AND MessageID > 0 " +
                            " " +
                            "UNION ALL " +
                            "   " +
                            "select 	M.[MessageID], M.[MailFrom], M.[MailFromHost], M.[RcptTo], M.[RcptToHost], M.[MessageSize], M.[ServerName], M.[Subject], M.[ServerIP], M.[ServerIPNum], M.[Datum],  " +
                            "	'ZERO' as  [Reason], M.[IncomingServer], M.[CheckSum], M.[XMailer], M.[XPriority], M.[XMSMailPriority], M.[XMimeOLE], M.[OriginatingHost], M.[CommunicationsLog], " +
                            "	1 as [Importing], M.ID as [ImportingID] " +
                            "from Mail M " +
                            "WHERE M.[Status] = '' AND M.MessageSize = 0   " +
                            "AND DATEDIFF(mi, M.Datum, CURRENT_TIMESTAMP) > 10 " +
                            "AND M.MessageID > 0 " +
                            " " +
                            "UNION ALL " +
                            "select 	M.[MessageID], M.[MailFrom], M.[MailFromHost], M.[RcptTo], M.[RcptToHost], M.[MessageSize], M.[ServerName], M.[Subject], M.[ServerIP], M.[ServerIPNum], M.[Datum],  " +
                            "	M.[Status] as  [Reason], M.[IncomingServer], M.[CheckSum], M.[XMailer], M.[XPriority], M.[XMSMailPriority], M.[XMimeOLE], M.[OriginatingHost], M.[CommunicationsLog], " +
                            "	1 as [Importing], M.ID as [ImportingID] " +
                            "from Mail M " +
                            "WHERE M.[Status] = 'FAIL' AND MessageSize = 0   " +
                            "AND MessageID > 0 ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MailComplete @MessageID bigint, @Status char(5), @ServerName varchar(255), @PreChecked int, @XMailer varchar(50), @XPriority varchar(50), " +
                            "	@XMSMailPriority varchar(50), @XMimeOLE varchar(50), @OriginatingHost varchar(255), @Subject nvarchar(255), @EIGHTBITMIME bit,  " +
                            "	@ErrorIncoming varchar(255), @CommunicationsLog nvarchar(max), @UsingTLS bit as " +
                            " " +
                            "UPDATE Mail  " +
                            "SET [Status] = @Status, Servername = @ServerName, PreChecked = @PreChecked,  " +
                            "  XMailer = @XMailer, XPriority = @XPriority, XMSMailPriority = @XMSMailPriority, XMimeOLE = @XMimeOLE,  " +
                            "  OriginatingHost = @OriginatingHost, [Subject] = @Subject, EIGHTBITMIME = @EIGHTBITMIME,  " +
                            "  ErrorIncoming = @ErrorIncoming, CommunicationsLog = @CommunicationsLog, UsingTLS = @UsingTLS " +
                            "WHERE MessageID = @MessageID  " +
                            " " +
                            "update Performance " +
                            "set LastMailReceived = GETUTCDATE() ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MailContentDeleteBulk @MessageIDs as MessageIDList readonly as " +
                            " " +
                            "delete T " +
                            "from MailContent T " +
                            "inner join @MessageIDs S on T.MessageID = S.MessageID ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MailContentGetAll as " +
                            " " +
                            "select top 5000 MessageID, BodyBinary, Datum " +
                            "from MailContent ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MailContentGetIDs as " +
                            " " +
                            "select MessageID " +
                            "from MailContent ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MailDeleteBulk @IDs as IDList readonly as " +
                            " " +
                            "delete T " +
                            "from Mail T " +
                            "inner join @IDs S on T.ID = S.ID ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MailForwardedDeleteBulk @IDs as IDList readonly as " +
                            " " +
                            "delete T " +
                            "from MailForwarded T " +
                            "inner join @IDs S on T.ID = S.ID ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MailForwardedGetAll as " +
                            " " +
                            "select 	M.[MessageID], M.[MailFrom], M.[MailFromHost], M.[RcptTo], M.[RcptToHost], M.[MessageSize], M.[ServerName], M.[Subject], M.[ServerIP], M.[ServerIPNum], M.[Datum],  " +
                            "	M.DatumDoorgestuurd, M.[Status] as  [Reason], M.[IncomingServer], M.[CheckSum], M.[XMailer], M.[XPriority], M.[XMSMailPriority], M.[XMimeOLE], M.[OriginatingHost], M.[CommunicationsLog], " +
                            "	1 as [Importing], M.ID as [ImportingID] " +
                            "from MailForwarded M ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MailForwardedGetIDs as " +
                            " " +
                            "select ID from MailForwarded ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MailGetIDs as " +
                            " " +
                            "select ID from Mail");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MailGrootteTeGaan @ID bigint, @Maat bigint as " +
                            " " +
                            "UPDATE Mail SET MessageSizeSent = MessageSize - @Maat WHERE ID = @ID");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MailVerzendenMislukt @ID bigint, @ErrorMessage varchar(255), @CommunicationsLog nvarchar(max) as " +
                            " " +
                            "IF (LEFT(@ErrorMessage,1) = '5' AND @ErrorMessage NOT LIKE '%SPF%')  " +
                            "BEGIN  " +
                            "	UPDATE Mail " +
                            "	SET ForwardingRetries = 11, ErrorForwarding = @ErrorMessage, CommunicationsLog = CommunicationsLog + @CommunicationsLog  " +
                            "	WHERE ID = @ID  " +
                            "END " +
                            "ELSE " +
                            "BEGIN " +
                            "	UPDATE Mail SET ForwardingRetries = ForwardingRetries +1, ErrorForwarding = @ErrorMessage " +
                            "	WHERE ID = @ID  " +
                            "END");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MailWaitingDeleteBulk @IDs as IDList readonly as " +
                            " " +
                            "delete T " +
                            "from Mail T " +
                            "inner join @IDs S on T.ID = S.ID ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MailWaitingGetAll as " +
                            " " +
                            "SELECT M.MessageID, M.MailFrom, M.MailFromHost, M.RcptTo, M.RcptToHost, M.MessageSize, M.ServerName, M.[Subject], M.ServerIP, M.ServerIPNum, M.Datum,  " +
                            "	M.[Status] as Reason, M.IncomingServer, M.[Checksum], M.XMailer, M.XPriority, M.XMSMailPriority, M.XMimeOLE, M.OriginatingHost, M.CommunicationsLog,  " +
                            "	M.Keywords, M.ErrorIncoming, M.ErrorFilter, M.ErrorForwarding, M.ForwardingRetries, M.ClientForward, M.PreChecked, 1 as Importing, ID as ImportingID " +
                            "FROM Mail  M " +
                            "WHERE (M.PreChecked = 0 OR M.PreChecked = 9)  " +
                            "AND M.[Status] <> 'RECV' AND Status <> 'FAIL' AND Status <> 'RSET' ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MarkRcptToHostAsNotBusy @RcptToHost varchar(255) AS " +
                            " " +
                            "update Mail " +
                            "set Busy = 0, ForwardingRetries = ForwardingRetries + 1 " +
                            "where RcptTohost = @RcptToHost " +
                            "and Busy = 1 ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MoveBadFreeMailToBad @ID bigint as " +
                            " " +
                            "UPDATE Mail SET PreChecked = 11, " +
                            "	Status = 'BLOCK',  " +
                            "	ErrorIncoming = 'Bad Free-Mail, content verified' " +
                            "WHERE ID = @ID");

                        GFS.SQL_SendQueryWithoutResponse("create procedure MoveUndeliverableToBad @ID bigint as " +
                            " " +
                            "UPDATE Mail SET PreChecked = 11,  " +
                            "	Status = 'BLOCK', " +
                            "	ErrorIncoming = 'Undeliverable Mail Forward'  " +
                            "WHERE MessageID = @ID");

                        GFS.SQL_SendQueryWithoutResponse("create procedure PerformanceGet as " +
                            " " +
                            "select IncomingStarting, ForwardingStarting, LastMailReceived, LastMailForwarded, " +
                            "(select count(*) from Mail where status = 'RECV') as [Receiving], " +
                            "(select count(*) from Mail where status = 'FAIL') as [Failed], " +
                            "(select count(*) from Mail where status = 'BLOCK') as [Blocked], " +
                            "(select count(*) from MailForwarded) as [Forwarded], " +
                            "(select count(*) from Mail where UsingTLS = 1)+(select count(*) from MailForwarded where UsingTLS = 1) as [TLS], " +
                            "(select count(*) from Mail where UsingTLS = 0)+(select count(*) from MailForwarded where UsingTLS = 0) as [NonTLS], " +
                            "IncomingProgress, " +
                            "(select count(*) from MailContent) as MailContentItems, " +
                            "isnull((select min(datum) from MailContent), GETUTCDATE()) as MailContentOldest, " +
                            "isnull((select max(datum) from MailContent), GETUTCDATE()) as MailContentYoungest, " +
                            "isnull((select sum(DATALENGTH(BodyBinary)) from MailContent), 0) as MailContentSize " +
                            "from Performance ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure PerformanceUpdateProgress @ID bigint as " +
                            " " +
                            "update Performance set IncomingProgress = @ID ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure RcptToHostData @RcptToHost varchar(255) as " +
                            " " +
                            "IF EXISTS (SELECT * FROM ForwardingSettings WHERE Domainname = @RcptToHost)  " +
                            "BEGIN  " +
                            "select 'JA' as Toegelaten, AllowAbused, MaxMessageSize " +
                            "	from ForwardingSettings " +
                            "	where Domainname = @RcptToHost " +
                            "END  " +
                            "ELSE  " +
                            "BEGIN  " +
                            "	SELECT 'NEEN' as Toegelaten, cast(0 as bit) as AllowAbused, 20971520 as MaxMessageSize " +
                            "END  ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure ResetBusyFlags as " +
                            " " +
                            "UPDATE Mail SET Busy = 0 WHERE Busy = 1 " +
                            " " +
                            "update Performance set ForwardingStarting = 1, LastMailForwarded = GETUTCDATE() ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure ServerUnreachable @ID bigint as " +
                            " " +
                            "UPDATE Mail  " +
                            "SET ForwardingRetries = ForwardingRetries +1  " +
                            "WHERE RcptToHost IN (SELECT RcptToHost FROM Mail WHERE ID = @ID)   " +
                            " " +
                            "UPDATE Mail  " +
                            "SET Busy = 0  " +
                            "WHERE ID = @ID");

                        GFS.SQL_SendQueryWithoutResponse("create procedure SubstituteEmailsSync @SubstituteEmails as STEs readonly as " +
                            " " +
                            "insert SubstituteEmails(ID, MailFrom, MailFromHost, RcptTo, RcptToHost, BeginDatum, EindDatum) " +
                            "select S.ID, S.MailFrom, S.MailFromHost, S.RcptTo, S.RcptToHost, S.BeginDatum, S.EindDatum " +
                            "from @SubstituteEmails S " +
                            "left outer join SubstituteEmails T on T.ID = S.ID " +
                            "where isnull(T.ID, 0) = 0 " +
                            " " +
                            "delete T " +
                            "from SubstituteEmails T " +
                            "left outer join @SubstituteEmails S on T.ID = S.ID " +
                            "where isnull(S.ID, 0) = 0 ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure UndeliverableSubjectSync @NDRs as NDRs readonly as " +
                            " " +
                            "insert UndeliverableSubjects(ID, [Subject], MailFrom) " +
                            "select S.ID, S.[Subject], S.MailFrom " +
                            "from @NDRs S " +
                            "left outer join UndeliverableSubjects T on T.ID = S.ID " +
                            "where isnull(T.ID, 0) = 0 " +
                            " " +
                            "delete T " +
                            "from UndeliverableSubjects T " +
                            "left outer join @NDRs S on T.ID = S.ID " +
                            "where isnull(S.ID, 0) = 0 ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure UserPreferencesSync @UserPreferences as UserPrefs readonly as " +
                            " " +
                            "insert UserPreferences(ID, EmailAddress, NoNDRs, ForwardFreeMails) " +
                            "select S.ID, S.EmailAddress, S.NoNDRs, S.ForwardFreeMails " +
                            "from @UserPreferences S " +
                            "left outer join UserPreferences T on T.ID = S.ID " +
                            "where isnull(T.ID, 0) = 0 " +
                            " " +
                            "delete T " +
                            "from UserPreferences T " +
                            "left outer join @UserPreferences S on T.ID = S.ID " +
                            "where isnull(S.ID, 0) = 0 ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure VoegToeMailHeaders @MessageID bigint, @XMailer varchar(50), @XPriority varchar(50), @XMSMailPriority varchar(50), " +
                            "	@XMimeOLE varchar(50), @OriginatingHost varchar(255), @Keywords nvarchar(512) as " +
                            " " +
                            "UPDATE Mail  " +
                            "SET XMailer = @XMailer, XPriority = @XPriority, XMSMailPriority = @XMSMailPriority, XMimeOLE = @XMimeOLE,  " +
                            "	OriginatingHost = @OriginatingHost, Keywords = @Keywords  " +
                            "WHERE MessageID = @MessageID ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure VoegToeMailSubject @MessageID bigint, @Subject nvarchar(255) as " +
                            " " +
                            "UPDATE Mail  " +
                            "SET [Subject] = @Subject  " +
                            "WHERE MessageID = @MessageID ");

                        GFS.SQL_SendQueryWithoutResponse("create procedure WissenOvergezetteMails as " +
                            " " +
                            "/* Bijwerken duidelijk mislukte mails */   " +
                            "UPDATE Mail  " +
                            "SET [Status]  = 'FAIL', PreChecked = 11  " +
                            "WHERE (([Status]  = 'RSET' OR [Status]  = 'RECV' OR [Status]  = 'FAIL')   " +
                            "AND ((MessageSize = 0 AND DATEDIFF(ss,Datum,CURRENT_TIMESTAMP) > 120 ) /* 120 seconden oud en geen lengte */        " +
                            "/* 120 sec + maat/2500 = 134 min voor 20MB, 124 sec voor 10kB */  " +
                            "OR ( MessageSize <> 0 AND DATEDIFF(ss,Datum,CURRENT_TIMESTAMP) > (MessageSize/2500+120)  )) )  " +
                            "OR ([Status]  = 'BLOCK' AND MessageSize = 0)    " +
                            " " +
                            "/* Wissen oude mails zonder MessageID */  " +
                            "delete from mail  " +
                            "WHERE MessageID = 0  " +
                            "AND DATEDIFF(mi, Datum, CURRENT_TIMESTAMP) > 5   " +
                            "   " +
                            "/* Wissen oude Undeliverables */  " +
                            "delete from UndeliverableInTime  " +
                            "where datediff(hour, tijdstip, current_timestamp) > 1");

                        // Triggers en indexes
                        GFS.SQL_SendQueryWithoutResponse("CREATE NONCLUSTERED INDEX FakeMailAddresses_Email ON FakeMailAddresses " +
                            "( Email ASC )");

                        GFS.SQL_SendQueryWithoutResponse("CREATE NONCLUSTERED INDEX GoodMailAddresses_Email ON GoodMailAddresses " +
                            "( Email ASC )");

                        GFS.SQL_SendQueryWithoutResponse("CREATE NONCLUSTERED INDEX Mail_Status ON Mail " +
                            "( [Status] ASC )");

                        GFS.SQL_SendQueryWithoutResponse("CREATE NONCLUSTERED INDEX Mail_Datum ON Mail " +
                            "( [Datum] ASC )");

                        GFS.SQL_SendQueryWithoutResponse("CREATE NONCLUSTERED INDEX Mail_PreChecked_MessageSize ON Mail " +
                            "( PreChecked asc, MessageSize asc ) include (Datum)");

                        GFS.SQL_SendQueryWithoutResponse("CREATE NONCLUSTERED INDEX Mail_MessageSize_Status ON Mail " +
                            "( MessageSize asc, [Status] ASC )");

                        GFS.SQL_SendQueryWithoutResponse("CREATE NONCLUSTERED INDEX Mail_Lots ON Mail " +
                            "( MessageSize asc, [Status] ASC, MessageID asc, [ID] asc, [Busy] asc ) " +
                            "include ([MailFrom], [MailFromHost], [RcptTo], [RcptToHost], [Subject], [ServerName], [ServerIP], [ServerIPNum], [Datum], " +
                            "[IncomingServer], [Checksum], [PreChecked], [XMailer], [XPriority], [XMSMailPriority], [XMimeOLE], [OriginatingHost], [CommunicationsLog])");

                        GFS.SQL_SendQueryWithoutResponse("CREATE NONCLUSTERED INDEX Mail_Busy ON Mail " +
                            "( [Busy] ASC )");

                        GFS.SQL_SendQueryWithoutResponse("CREATE NONCLUSTERED INDEX MailForwarded_Datum ON MailForwarded " +
                            "( Datum asc ) include (DatumDoorgestuurd)");

                        GFS.SQL_SendQueryWithoutResponse("CREATE NONCLUSTERED INDEX MailForwarded_DatumDoorgestuurd ON MailForwarded " +
                            "( DatumDoorgestuurd asc )");

                        // Create Alarm user
                        GFS.SQL_SendWithoutResponse("sp_addlogin", new List<SqlParameter>() {
                            new SqlParameter(){ParameterName = "@loginame", SqlDbType = SqlDbType.VarChar, Size = 255, Value = "Alarm" },
                            new SqlParameter(){ParameterName = "@passwd", SqlDbType = SqlDbType.VarChar, Size = 255, Value = "Alertgeneral!!" },
                            new SqlParameter(){ParameterName = "@defdb", SqlDbType = SqlDbType.VarChar, Size = 255, Value = "Spamfilter" }});

                        GFS.SQL_SendWithoutResponse("sp_grantdbaccess", new List<SqlParameter>() {
                            new SqlParameter(){ParameterName = "@loginame", SqlDbType = SqlDbType.VarChar, Size = 255, Value = "Alarm" }});

                        // Set Rights for Alarm
                        GFS.SQL_SendQueryWithoutResponse("GRANT EXECUTE ON HaalControleMetingen TO Alarm");


                        // All set up: start sync
                        GFS.SQL_SendWithoutResponse(SQLconnRemote, "GeneralSettingsEnableServer");
                    }
                }
            }
            catch (Exception eee)
            {
                GFS.LogError(eee, EventLogEntryType.FailureAudit, 2010032140, true);
            }
        }

        protected override void OnStop()
        {
            while (ExecutingMetingForwarded)
                Thread.Sleep(100);
        }
        public void ControlesUitvoeren()
        {
            int Looper = 0;

            while (true)
            {
                try
                {
                    Process[] AlleProcessen = Process.GetProcesses();
                    List<string> Processen = new List<string>() { };
                    Int64 ForwardingMemoryUsed = 0;
                    Int64 IncomingMemoryUsed = 0;

                    foreach (Process pp in AlleProcessen)
                    {
                        Processen.Add(pp.ProcessName.ToLower());
                        if (pp.ProcessName.ToLower() == "forwarding service v6")
                            ForwardingMemoryUsed = pp.PrivateMemorySize64;
                        if (pp.ProcessName.ToLower() == "incoming service v6")
                            IncomingMemoryUsed = pp.PrivateMemorySize64;
                    }

                    if (Environment.MachineName.ToLower() == "yoda")
                    {
                        try
                        {
                            if (!Processen.Contains("forwarding service v6"))
                            { // service stilgevallen, terug opzetten
                                GFS.LogError("Restarting the Forwarding Service, it was stoppped", EventLogEntryType.Warning, 2009282352, true);
                                using (ServiceController serviceControllerForwarding = new ServiceController("ForwardingService"))
                                {
                                    if (serviceControllerForwarding.Status.ToString().ToLower() != "stopped")
                                    {
                                        serviceControllerForwarding.Stop();
                                        GFS.LogError("Stop command sent for Forwarding Service", EventLogEntryType.Warning, 2009282353, false);
                                    }
                                    serviceControllerForwarding.Start();
                                }
                                GFS.LogError("Start command sent for Forwarding Service", EventLogEntryType.Warning, 2009282354, false);
                            }
                        }
                        catch (Exception eee)
                        {
                            GFS.LogError(eee, EventLogEntryType.FailureAudit, 2009282355, true);
                        }
                    }

                    try
                    {
                        ServiceController[] Services = ServiceController.GetServices();
                        bool ProcessStopping = false;

                        foreach (ServiceController Service in Services)
                        {
                            if (Service.ServiceName == "ForwardingService")
                            {
                                ProcessStopping = Service.Status.ToString() == "Stopping" || Service.Status.ToString() == "StopPending";
                                break;
                            }
                        }

                        if (ProcessStopping)
                        {
                            Thread.Sleep(3000);
                            Services = ServiceController.GetServices();

                            foreach (ServiceController Service in Services)
                            {
                                if (Service.ServiceName == "ForwardingService")
                                {
                                    if (Service.Status.ToString() == "Stopping" || Service.Status.ToString() == "StopPending")
                                    {
                                        foreach (Process pp in Process.GetProcesses())
                                        {
                                            if (pp.ProcessName.ToLower() == "forwarding service v6")
                                            {
                                                pp.Kill();
                                                GFS.LogError("Forwarding Service seems to hang, killing...", EventLogEntryType.FailureAudit, 2009282356, true);
                                                break;
                                            }
                                        }
                                        break;
                                    }
                                }
                            }
                        }

                        if (!Processen.Contains("forwarding service v6"))
                        { // service stilgevallen, terug opzetten
                            GFS.LogError("Restarting the Forwarding Service, it was stoppped", EventLogEntryType.Warning, 2009282359, true);
                            using (ServiceController serviceControllerForwarding = new ServiceController("ForwardingService"))
                            {
                                if (serviceControllerForwarding.Status.ToString().ToLower() != "stopped")
                                {
                                    serviceControllerForwarding.Stop();
                                    GFS.LogError("Stop command sent for Forwarding Service", EventLogEntryType.Warning, 2009282357, false);
                                }
                                serviceControllerForwarding.Start();
                            }
                            GFS.LogError("Start command sent for Forwarding Service", EventLogEntryType.Warning, 2009282358, false);
                        }

                        if (Environment.MachineName.ToLower() == "yoda")
                        {
                            if (!Processen.Contains("sqlagent"))
                            { // service stilgevallen, terug opzetten
                                GFS.LogError("Restarting the SQL Agent, it was stoppped", EventLogEntryType.Warning, 2009290000, true);
                                using (ServiceController serviceControllerSQLAgent = new ServiceController("sqlserveragent"))
                                {
                                    if (serviceControllerSQLAgent.Status.ToString().ToLower() != "stopped")
                                    {
                                        serviceControllerSQLAgent.Stop();
                                        GFS.LogError("Stop command sent for SQL Agent", EventLogEntryType.Warning, 2009290001, false);
                                    }
                                    serviceControllerSQLAgent.Start();
                                }
                                GFS.LogError("Start command sent for SQL Agent", EventLogEntryType.Warning, 2009290002, false);
                            }
                        }

                        if (Environment.MachineName.ToLower() != "yoda")
                        {
                            if (!Processen.Contains("incoming service v6"))
                            { // service stilgevallen, terug opzetten
                                GFS.LogError("Restarting the Incoming Service, it was stoppped", EventLogEntryType.Warning, 2009290003, true);
                                using (ServiceController serviceControllerIncoming = new ServiceController("IncomingService"))
                                {
                                    if (serviceControllerIncoming.Status.ToString().ToLower() != "stopped")
                                    {
                                        serviceControllerIncoming.Stop();
                                        GFS.LogError("Stop command sent for Incoming Service", EventLogEntryType.Warning, 2009290004, false);
                                    }
                                    serviceControllerIncoming.Start();
                                }
                                GFS.LogError("Start command sent for Incoming Service", EventLogEntryType.Warning, 2009290005, false);
                            }
                            else if (IncomingMemoryUsed > (Int64)(12 * 1024) * (Int64)1024 * (Int64)1024)
                            {
                                StopIncomingService();
                                GFS.LogError("Stoppnig Incoming Service, more than 12GB in use", EventLogEntryType.Warning, 2009290006, false);
                            }
                        }
                        if (OpenConnecties > 200 && !OpenConnectiesGereageerd)
                        {
                            OpenConnectiesGereageerd = true;
                            StopIncomingService();
                            GFS.LogError("Restarting Incoming Service, too many unfinished connections", EventLogEntryType.Warning, 2009290008, false);
                        }
                        else if (OpenConnecties < 200)
                        {
                            OpenConnectiesGereageerd = false;
                        }

                        if (!CheckIncomingStarting)
                        {
                            if ((DateTime.UtcNow - CheckLastMailReceived).TotalSeconds > 600)
                            {
                                StopIncomingService();
                                GFS.LogError("Restarting Incoming Service, no mail in a long time", EventLogEntryType.Warning, 2010071121, false);
                                CheckIncomingStarting = true;
                            }
                            else if ((DateTime.UtcNow - CheckLastMailReceived).TotalSeconds > 300)
                            {
                                if (!TestingIncomingMail)
                                {
                                    try
                                    {
                                        using (SmtpClient Server = new SmtpClient("localhost"))
                                        using (MailMessage Message = new MailMessage($"{Environment.MachineName.ToLower()}@spamfilter.be", "internal.test@spamfilter.be", DateTime.UtcNow.ToBinary().ToString(), "Test mail. content unimportant"))
                                        {
                                            GFS.LogError($"Long time no incoming mails. Sending test mail to internal.test@spamfilter.be from {Environment.MachineName.ToLower()}@spamfilter.be using localhost", 
                                                EventLogEntryType.Information, 2012231227, true);
                                            Server.Send(Message);
                                        }
                                        TestingIncomingMail = true;
                                    }
                                    catch (Exception eee)
                                    {
                                        GFS.LogError(eee, EventLogEntryType.FailureAudit, 2012022118, true);
                                    }
                                }
                            }
                            else
                            {
                                TestingIncomingMail = false;
                            }
                        }

                        if (!CheckForwardingStarting)
                        {
                            if ((DateTime.UtcNow - CheckLastMailForwarded).TotalSeconds > 600)
                            {
                                StopForwardingService();
                                ControleerDoorsturenOp = DateTime.Now.AddMinutes(10);
                                GFS.LogError("Stopping Forwarding Service, no mails forwarded in over an hour.", EventLogEntryType.Warning, 2010071126, false);
                                CheckForwardingStarting = true;
                            }
                            else if ((DateTime.UtcNow - CheckLastMailForwarded).TotalSeconds > 300)
                            {
                                if (!TestingOutgoingMail)
                                {
                                    try
                                    {
                                        using (SmtpClient Server = new SmtpClient("localhost"))
                                        using (MailMessage Message = new MailMessage($"{Environment.MachineName.ToLower()}@spamfilter.be", "internal.test@spamfilter.be", DateTime.UtcNow.ToBinary().ToString(), "Test mail. content unimportant"))
                                        {
                                            GFS.LogError($"Long time no outgoing mails. Sending test mail to internal.test@spamfilter.be from {Environment.MachineName.ToLower()}@spamfilter.be using localhost",
                                                EventLogEntryType.Information, 2012231120, true);
                                            Server.Send(Message);
                                        }
                                        TestingOutgoingMail = true;
                                    }
                                    catch (Exception eee)
                                    {
                                        GFS.LogError(eee, EventLogEntryType.FailureAudit, 2012022117, true);
                                    }
                                }
                            }
                            else
                            {
                                TestingOutgoingMail = false;
                            }
                        }
                    }
                    catch (Exception eee)
                    {
                        GFS.LogError(eee, EventLogEntryType.FailureAudit, 2009290009, true);
                    }

                    if (Environment.MachineName.ToLower() != "yoda")
                    {
                        if (DateTime.Now.Minute == 30)
                        {
                            try
                            {
                                object objTime = GFS.SQL_SendQueryWithObjectResponse(SQLconnRemote, "select CURRENT_TIMESTAMP");

                                if (objTime != null)
                                {
                                    DateTime RemoteTime = DateTime.Parse(objTime.ToString());

                                    if (((int)(RemoteTime - DateTime.Now).TotalSeconds / 10) != 0)
                                    {
                                        ProcessStartInfo info = new ProcessStartInfo();
                                        info.UseShellExecute = false;
                                        info.RedirectStandardInput = true;
                                        info.RedirectStandardOutput = true;
                                        info.CreateNoWindow = true;
                                        info.FileName = "cmd";
                                        info.Arguments = "/k time " + RemoteTime.ToLongTimeString();

                                        Process ns = Process.Start(info);

                                        GFS.LogError($"Updated the time using : {info.FileName} {info.Arguments}", EventLogEntryType.Information, 20092333, true);
                                    }
                                }
                            }
                            catch (Exception eee)
                            {
                                GFS.LogError(eee, EventLogEntryType.FailureAudit, 2009282335, true);
                            }
                        }
                    }

                    if (Looper % 6 == 5)
                    {
                        try
                        {
                            OpenConnecties = GF.IntParse(GFS.SQL_SendQueryWithObjectResponse("select count(*) from mail where status = 'recv'"));
                        }
                        catch (Exception eee)
                        {
                            GFS.LogError(eee, EventLogEntryType.FailureAudit, 2009282345, true);
                        }

                        try
                        {
                            GFS.SQL_SendWithoutResponse("WissenOvergezetteMails");
                        }
                        catch (Exception eee)
                        {
                            GFS.LogError(eee, EventLogEntryType.FailureAudit, 2010032127, true);
                        }

                        try
                        {
                            DataTable dtResult = GFS.SQL_SendWithDirectDataTableResponse("PerformanceGet");
                            if (dtResult.Rows.Count > 0)
                            {
                                CheckIncomingStarting = (bool)dtResult.Rows[0]["IncomingStarting"];
                                CheckForwardingStarting = (bool)dtResult.Rows[0]["ForwardingStarting"];
                                CheckLastMailReceived = (DateTime)dtResult.Rows[0]["LastMailReceived"];
                                CheckLastMailForwarded = (DateTime)dtResult.Rows[0]["LastMailForwarded"];
                            }
                        }
                        catch (Exception eee)
                        {
                            GFS.LogError(eee, EventLogEntryType.FailureAudit, 2010032127, true);
                        }
                    }
                }
                catch (Exception eee)
                {
                    GFS.LogError(eee, EventLogEntryType.FailureAudit, 2009282320, true);
                }

                Thread.Sleep(10000);
                Looper++;
            }
        }

        private void StopIncomingService()
        {
            try
            {
                using (ServiceController serviceControllerIncoming = new ServiceController("IncomingService"))
                {
                    serviceControllerIncoming.Stop();
                }
            }
            catch (Exception)
            {

            }

            Thread.Sleep(3000);

            foreach (Process pp in Process.GetProcesses())
            {
                if (pp.ProcessName.ToLower() == "incoming service v6")
                {
                    pp.Kill();
                    GFS.LogError("Incoming Service is stuck, killing...", EventLogEntryType.FailureAudit, 2010081446, true);
                    break;
                }
            }
        }

        private void StopForwardingService()
        {
            try
            {
                using (ServiceController serviceControllerIncoming = new ServiceController("ForwardingService"))
                {
                    serviceControllerIncoming.Stop();
                }
            }
            catch (Exception)
            {

            }

            Thread.Sleep(3000);

            foreach (Process pp in Process.GetProcesses())
            {
                if (pp.ProcessName.ToLower() == "forwarding service v6")
                {
                    pp.Kill();
                    GFS.LogError("Forwarding Service is stuck, killing...", EventLogEntryType.FailureAudit, 2010081451, true);
                    break;
                }
            }
        }
    }
}