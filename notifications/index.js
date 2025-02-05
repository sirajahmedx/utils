const nodemailer = require("nodemailer");

async function SendEmail(to, subject, otp) {
   try {
      const transporter = nodemailer.createTransport({
         service: "gmail", // Use "Outlook", "Yahoo", or any SMTP service
         auth: {
            user: process.env.EMAIL_USER, // Your email address
            pass: process.env.EMAIL_PASS, // Your email password or App Password
         },
      });

      const mailOptions = {
         from: process.env.EMAIL_USER,
         to,
         subject,
         text: `Your OTP is: ${otp}`,
      };

      await transporter.sendMail(mailOptions);
      return true;
   } catch (error) {
      console.error("Email sending failed:", error);
      return false;
   }
}

module.exports = { SendEmail };
