using Microsoft.AspNetCore.Mvc;

namespace DemoDotNet8.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;
        private readonly string _apiVersion;

        public WeatherForecastController(ILogger<WeatherForecastController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _apiVersion = configuration["ApiVersion"] ?? "unknown";
        }

        [HttpGet(Name = "GetWeatherForecast")]
        public IActionResult Get()
        {
            var forecasts = Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();

            return Ok(new
            {
                ApiVersion = _apiVersion,
                Forecasts = forecasts
            });
        }

        [HttpGet("environment")]
        public IActionResult GetEnvironmentVariables()
        {
            var environmentVariables = Environment
                .GetEnvironmentVariables()
                .Cast<System.Collections.DictionaryEntry>()
                .ToDictionary(entry => entry.Key?.ToString() ?? string.Empty, entry => entry.Value?.ToString());

            return Ok(new
            {
                ApiVersion = _apiVersion,
                EnvironmentVariables = environmentVariables
            });
        }

        [HttpGet("instance-info")]
        public IActionResult GetInstanceInfo()
        {
            var instanceId = Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID") ?? "unknown";
            var instanceName = Environment.GetEnvironmentVariable("COMPUTERNAME") ?? "unknown";

            return Ok(new
            {
                ApiVersion = _apiVersion,
                InstanceId = instanceId,
                InstanceName = instanceName
                
            });
        }
    }
}
