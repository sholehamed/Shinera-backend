using Microsoft.AspNetCore.HttpOverrides;
using Modules.System.FileStorage;
using Modules.System.Identity;
using Scalar.AspNetCore;
using Scalar.ClientGeneration;

namespace Server
{
    public static class DependencyInjections
    {
        public static void RegisterServices(this WebApplicationBuilder builder)
        {
            builder.Services.AddOpenApi();
            builder.Services.AddAntiforgery();
            builder.Services.AddMediaStorage(builder.Configuration);
            builder.Services.AddIdentityModule(builder.Configuration);
            builder.Services.AddScalarClientGeneration();

            // Salon Modules


            string[] r = builder.Configuration["Cors"]!.Split(",");
            builder.Services.AddCors(options =>
            {
                options.AddPolicy("Cors", policy =>
                {
                    policy
                        .WithOrigins(builder.Configuration["Cors"]!.Split(','))
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
            });
        }
        public static void RegisterApps(this WebApplication app, IConfiguration configuration)
        {
            app.UseForwardedHeaders(new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
            });

            app.UseCors("Cors");
            app.UseMediaStorage(configuration);
            app.UseIdentityModule(configuration);

            // Salon Modules
          

            app.UseAntiforgery();
            if (app.Environment.IsDevelopment())
            {
                app.MapOpenApi();
                app.MapScalarClientGenerationAssets();
                app.MapScalarWithClientGeneration("apis");
            }

        }
    }
}
