// SMS service for notifications
const sendSMS = async (phone, message) => {
    // Add SMS API integration here
    console.log(`SMS to ${phone}: ${message}`);
};

module.exports = { sendSMS };