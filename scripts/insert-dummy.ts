import { initDatabase, insertQuarantine, listAccounts } from '../src/db/index.js';

async function main() {
    await initDatabase();
    const accounts = await listAccounts();
    const accountId = accounts.length > 0 ? accounts[0].id : 'default';

    const dummyEmails = [
        {
            id: "q-req-" + Date.now(),
            direction: "inbound",
            from_addr: "spammy.bot@marketing-xyz.com",
            to_addr: "alice@example.com",
            subject: "You've Won a Free Gift Card!",
            body_preview: "Click here now to claim your $500 Amazon gift card before the offer expires in 10 minutes...",
            raw_eml: Buffer.from("From: spammy.bot@marketing-xyz.com\nTo: alice@example.com\nSubject: You've Won a Free Gift Card!\n\nClick here now to claim your $500 Amazon gift card before the offer expires in 10 minutes..."),
            reason: "High probability of phishing/scam based on subject and urgency.",
            categories: ["Phishing", "Spam", "Scam"],
            confidence: 0.98,
            accountId
        },
        {
            id: "q-req-" + (Date.now() + 1),
            direction: "inbound",
            from_addr: "info@newsletter-weekly.com",
            to_addr: "alice@example.com",
            subject: "Weekly Deals & Offers",
            body_preview: "Check out this week's top software deals, including huge discounts on productivity tools.",
            raw_eml: Buffer.from("From: info@newsletter-weekly.com\nTo: alice@example.com\nSubject: Weekly Deals & Offers\n\nCheck out this week's top software deals, including huge discounts on productivity tools."),
            reason: "Bulk promotional newsletter not explicitly requested by user.",
            categories: ["Promotional", "Bulk"],
            confidence: 0.85,
            accountId
        }
    ];

    for (const email of dummyEmails) {
        await insertQuarantine({
            ...email,
            raw_eml: email.raw_eml
        });
    }

    console.log("Dummy quarantine entries inserted successfully.");
    process.exit(0);
}

main().catch(console.error);
