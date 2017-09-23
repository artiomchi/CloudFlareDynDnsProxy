using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace CloudFlareDynDnsProxy
{
    public class Startup
    {
        private IConfiguration Configuration { get; }
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.Map("/checkip", mapApp => mapApp.Run(CheckIP));

            app.Map("/nic/update", mapApp => mapApp.Use(NicUpdate));
        }

        public Task CheckIP(HttpContext context) => context.Response.WriteAsync(context.Connection.RemoteIpAddress.ToString());

        private async Task NicUpdate(HttpContext context, Func<Task> next)
        {
            String authHeader = context.Request.Headers["Authorization"];
            if (authHeader == null || !authHeader.StartsWith("basic", StringComparison.OrdinalIgnoreCase))
            {
                await context.Response.WriteAsync("badauth");
                return;
            }

            var token = authHeader.Substring("Basic ".Length).Trim();
            var credentialstring = Encoding.UTF8.GetString(Convert.FromBase64String(token));

            var config = Configuration.GetSection("CloudFlare:" + credentialstring);
            if (config == null)
            {
                await context.Response.WriteAsync("badauth");
                return;
            }

            var zone = config["Zone"];
            var identifier = config["Identifier"];
            var authEmail = config["AuthEmail"];
            var authKey = config["AuthKey"];
            if (String.IsNullOrWhiteSpace(zone) ||
                String.IsNullOrWhiteSpace(identifier) ||
                String.IsNullOrWhiteSpace(authEmail) ||
                String.IsNullOrWhiteSpace(authKey))
            {
                await context.Response.WriteAsync("badauth");
                return;
            }

            string hostname = context.Request.Query["hostname"];
            if (string.IsNullOrWhiteSpace(hostname))
            {
                await context.Response.WriteAsync("nohost");
                return;
            }
            var myip = context.Request.Query["myip"].FirstOrDefault() ?? context.Connection.RemoteIpAddress.ToString();

            var content = JsonConvert.SerializeObject(new
            {
                type = "A",
                name = hostname,
                content = myip
            });
            using (var client = new HttpClient
            {
                BaseAddress = new Uri($"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/{identifier}"),
                DefaultRequestHeaders =
                {
                    { "X-Auth-Email", authEmail },
                    { "X-Auth-Key", authKey },
                }
            })
            using (var response = await client.PutAsync("", new StringContent(content, Encoding.UTF8, "application/json")))
            {
                if (!response.IsSuccessStatusCode)
                {
                    await context.Response.WriteAsync("911");
                    return;
                }

                var resultJson = await response.Content.ReadAsStringAsync();
                var result = JsonConvert.DeserializeObject(resultJson) as JObject;
                if (!result["success"].Value<bool>())
                {
                    await context.Response.WriteAsync("911");
                    return;
                }

                await context.Response.WriteAsync("ok");
            }
        }
    }
}
