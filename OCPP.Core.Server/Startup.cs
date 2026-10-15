/*
 * OCPP.Core - https://github.com/dallmann-consulting/OCPP.Core
 * Copyright (C) 2020-2021 dallmann consulting GmbH.
 * All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net.WebSockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using OCPP.Core.Database;

namespace OCPP.Core.Server
{
    public class Startup
    {
        /// <summary>
        /// ILogger object
        /// </summary>
        private ILoggerFactory LoggerFactory { get; set; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddOCPPDbContext(Configuration);
            services.AddControllers();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        //public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        public void Configure(IApplicationBuilder app,
                            IWebHostEnvironment env,
                            ILoggerFactory loggerFactory,
                            IServiceScopeFactory serviceScopeFactory)
        {
            LoggerFactory = loggerFactory;
            ILogger logger = loggerFactory.CreateLogger(typeof(Startup));
            logger.LogTrace("Startup => Configure(...)");

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            // After a reboot the database server (e.g. SQL-Server service) may not be ready yet.
            // An exception here would leave IIS with a failed app (HTTP 500.30) until the app pool is restarted
            // => wait a limited time (below the IIS startupTimeLimit of 120s), then continue startup
            //    and keep trying in the background
            int dbStartupTimeout = Configuration.GetValue<int>("DbStartupTimeout", 60);
            if (!InitDatabase(serviceScopeFactory, logger, DateTime.Now.AddSeconds(dbStartupTimeout)))
            {
                logger.LogError("Startup => Database not ready after {0} seconds => continue startup and retry in background", dbStartupTimeout);
                Task.Run(() => InitDatabase(serviceScopeFactory, logger, DateTime.MaxValue));
            }

            // Set WebSocketsOptions
            var webSocketOptions = new WebSocketOptions() 
            {
            };

            // Accept WebSocket
            app.UseWebSockets(webSocketOptions);

            // Integrate custom OCPP middleware for message processing
            app.UseOCPPMiddleware();
        }

        /// <summary>
        /// Migrates the database (or only checks the connection when "AutoMigrateDB" is disabled).
        /// Retries every 5 seconds until success or until 'waitUntil' is reached.
        /// </summary>
        private bool InitDatabase(IServiceScopeFactory serviceScopeFactory, ILogger logger, DateTime waitUntil)
        {
            // Migration only when not disabled (needs admin permissions in SQL-Server!)
            bool dbMigrate = Configuration.GetValue<bool>("AutoMigrateDB", true);
            int attempt = 0;
            while (true)
            {
                attempt++;
                try
                {
                    using var scope = serviceScopeFactory.CreateScope();
                    var dbContext = scope.ServiceProvider.GetRequiredService<OCPPCoreContext>();
                    if (dbMigrate)
                    {
                        dbContext.Database.Migrate();
                    }
                    else if (!dbContext.Database.CanConnect())
                    {
                        throw new InvalidOperationException("Database not reachable");
                    }
                    logger.LogInformation("Startup => Database ready (attempt {0})", attempt);
                    return true;
                }
                catch (Exception exp)
                {
                    if (DateTime.Now >= waitUntil) return false;
                    logger.LogWarning("Startup => Database not ready (attempt {0}): {1} => retry in 5 seconds", attempt, exp.Message);
                    Thread.Sleep(5000);
                }
            }
        }
    }
}
