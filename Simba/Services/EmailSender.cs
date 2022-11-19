using Microsoft.AspNetCore.Identity.UI.Services;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace Simba.Services
{
    public class EmailSender: IEmailSender
    {
        private readonly ILogger _logger;
        private readonly IConfiguration _configuration;

        public EmailSender(ILogger<EmailSender> logger,
                           IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string message)
        {
            if (subject == "Reset Password")
                await ExecuteResetPass(_configuration["SendGridKey"], subject, message, toEmail);
            else if (subject == "Confirm Email")
                await ExecuteConfirmEmail(_configuration["SendGridKey"], subject, message, toEmail);
        }

        public async Task ExecuteResetPass(string apiKey, string subject, string message, string toEmail)
        {
            var client = new SendGridClient(apiKey);
            var msg = new SendGridMessage();
            msg.SetFrom("XX");
            msg.AddTo(new EmailAddress(toEmail));
            msg.SetTemplateId("XX");

            var dynamicTemplateData = new
            {
                subject = subject,
                resetUrl = message
            };

            msg.SetTemplateData(dynamicTemplateData);
            //msg.SetClickTracking(false, false);
            var response = await client.SendEmailAsync(msg);
            _logger.LogInformation(response.IsSuccessStatusCode
                                   ? $"Email to {toEmail} queued successfully!"
                                   : $"Failure Email to {toEmail}");
        }

        public async Task ExecuteConfirmEmail(string apiKey, string subject, string message, string toEmail)
        {
            var client = new SendGridClient(apiKey);
            var msg = new SendGridMessage();

            msg.SetFrom("XX");
            msg.AddTo(new EmailAddress(toEmail));
            msg.SetTemplateId("XX");

            var dynamicTemplateData = new
            {
                subject = subject,
                resetUrl = message
            };

            msg.SetTemplateData(dynamicTemplateData);
            //msg.SetClickTracking(false, false);
            var response = await client.SendEmailAsync(msg);
            _logger.LogInformation(response.IsSuccessStatusCode
                                   ? $"Email to {toEmail} queued successfully!"
                                   : $"Failure Email to {toEmail}");
        }
    }
}
