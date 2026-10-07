# Spam guard bot

A Discord bot that removes scam images, scam links, malicious invites, hiring
spam, and raids from one Discord server. When a message matches a rule, the bot:

1. Times out the author.
2. Deletes the message (and a thread the author started from it).
3. Posts an alert in the moderation channel with the author, the channel, the
   message or the text read from the image, and the rule that matched.

All settings come from environment variables. The bot has no database. While
running, it writes nothing to disk except its OCR model cache.

## What leaves the server

| Destination | What and why |
| --- | --- |
| Discord API | Normal bot traffic: receiving messages, deleting, timing out, posting alerts, resolving invite links. |
| Discord CDN | Downloads attached and embedded images to scan them. Only Discord image hosts are allowed. |
| huggingface.co (github.com as fallback) | On first start, downloads about 30 MB of OCR model files. Download only; nothing is uploaded. |

Alerts and feedback reports only go to channels you configure.

## Setup

Every step below is required unless it says optional.

### 1. Create the Discord application

1. Open the [Discord Developer Portal](https://discord.com/developers/applications)
   and create an application.
2. On the **Bot** page:
   - Select **Reset Token** and copy the token. This is `DISCORD_TOKEN`.
   - Turn **off** **Public Bot**. Only the application's owner (or its
     developer team) can then add the bot to a server.
   - Under **Privileged Gateway Intents**, turn **on** **Message Content
     Intent**. Without it the bot cannot read message text.
3. Copy the **Application ID** from the **General Information** page.

### 2. Add the bot to the server

Open this URL with your application ID filled in, and pick the server:

```text
https://discord.com/oauth2/authorize?client_id=YOUR_APPLICATION_ID&scope=bot&permissions=1116691622912
```

That permission number grants exactly what the bot uses:

| Permission | Used for |
| --- | --- |
| View Channels, Read Message History | Reading messages to scan them. |
| Send Messages, Embed Links | Posting alerts. |
| Attach Files | Attaching images to feedback reports. |
| Manage Messages | Deleting spam. |
| Manage Threads | Deleting threads that spammers create. |
| Moderate Members | Timing out spammers. |

Then, in **Server Settings > Roles**, drag the bot's role **above** every role
it should be able to time out. Discord does not let a bot time out members
whose highest role is above its own, administrators, or the server owner.

### 3. Create the moderation channel

Create a channel that only moderators can see. The bot needs View Channel,
Send Messages, and Embed Links there. If you set `FEEDBACK_CHANNEL_ID`, the
bot also needs Attach Files in that channel, because feedback copies include
the images. If either channel is a thread, the bot needs Send Messages in
Threads instead of Send Messages.

To copy IDs, turn on **User Settings > Advanced > Developer Mode**, then
right-click a channel or role and select **Copy ID**.

### 4. Install on the server

You need an Ubuntu or Debian server with at least 4 GB of RAM, logged in as
root. Run:

```bash
apt-get install -y git
git clone https://github.com/appwrite-labs/spam-guard-bot.git /opt/spam-guard-bot
/opt/spam-guard-bot/scripts/install.sh
```

The install script:

1. Installs Node.js 22 and pnpm, if they are missing.
2. Installs the bot's dependencies.
3. Creates `/opt/spam-guard-bot/.env` from `.env.example` and asks you to
   paste the bot token. The token stays hidden while you paste it.
4. Installs and starts the `spam-guard-bot` service, which also starts the bot
   whenever the server reboots.
5. Shows the bot's first log lines.

`.env.example` is already filled in for the Appwrite server. See
[Configuration](#configuration) for every setting.

When the bot is running, the log lines include:

```text
Bot connected as YourBot#1234.
Moderating "Your Server" (123456789012345678). Alerts go to #mod-alerts.
```

If the script says the bot is not running, the log lines below that message
explain why, for example a missing channel permission. Fix it and run the
script again. It is safe to run as often as you like: it skips steps that are
already done and keeps your `.env`.

The first image the bot reads downloads about 30 MB of OCR models from
huggingface.co, so the server needs internet access.

### 5. Check it works

From a test account that is not an admin and has none of the excluded roles,
post this in any channel:

```text
Free crypto giveaway! Send crypto to receive double back.
```

The message should disappear, the test account should be timed out, and an
alert should appear in the moderation channel. Remove the test account's
timeout afterwards: right-click it, then select **Remove Timeout**.

## Running the bot

### Updating

```bash
/opt/spam-guard-bot/scripts/update.sh
```

This downloads the latest code, updates the dependencies, and restarts the bot.
Your `.env` is kept.

### Everyday commands

| To | Run |
| --- | --- |
| Check the bot is running | `systemctl status spam-guard-bot` |
| Watch the logs (Ctrl+C to stop watching) | `journalctl -u spam-guard-bot -f` |
| Change a setting | `nano /opt/spam-guard-bot/.env`, then `systemctl restart spam-guard-bot` |
| Restart the bot | `systemctl restart spam-guard-bot` |
| Stop the bot | `systemctl stop spam-guard-bot` |

### If the bot keeps failing to start

After 5 failed starts in an hour, systemd stops restarting the bot. This
protects the bot token: Discord resets a bot's token after 1,000 logins in 24
hours. Fix the cause shown in the logs, then run
`/opt/spam-guard-bot/scripts/install.sh` again, which also clears that limit.

The service file is `deploy/spam-guard-bot.service`. Edit it there, not in
`/etc/systemd/system/`: the install and update scripts overwrite the installed
copy.

### Running without the script

On other systems, or to try the bot locally, install Node.js 22 and pnpm 10,
then from the repository folder:

```bash
pnpm install --prod --frozen-lockfile
cp .env.example .env   # then add DISCORD_TOKEN
pnpm start
```

`pnpm install` prints `Ignored build scripts: onnxruntime-node`. This is
expected: that script only downloads optional GPU files. If you run the bot
under another process manager, limit how often it restarts, for the token
reason above.

## Configuration

Only `DISCORD_TOKEN` and `MODERATION_CHANNEL_ID` are required. Everything else
has the default shown. `.env.example` lists the same settings with comments.
Restart the bot after changing any of them. An invalid value stops the bot at
startup with an error naming the variable.

### Channels

| Variable | Default | What it does |
| --- | --- | --- |
| `DISCORD_TOKEN` | required | Bot token from the Developer Portal. |
| `MODERATION_CHANNEL_ID` | required | Channel for moderation alerts. The bot only moderates the server this channel is in. |
| `FEEDBACK_CHANNEL_ID` | empty (off) | When set, image and hiring-ad alerts get **False detection** and **Correct detection** buttons. Clicking one posts a copy of the case (message text, text read from the image, images, who clicked) to this channel, to collect mistakes for tuning. Can be the same as `MODERATION_CHANNEL_ID`. |

### Who is never checked

| Variable | Default | What it does |
| --- | --- | --- |
| `EXCLUDED_ROLE_IDS` | empty | Comma-separated role IDs. Members with any of these roles are skipped. |
| `EXCLUDE_ADMINS` | `true` | Skips the server owner and members with the Administrator permission. |
| `MODERATE_BOTS` | `false` | Also checks messages from other bots. Webhooks and the bot itself are never checked. |

### Punishment

| Variable | Default | What it does |
| --- | --- | --- |
| `TIMEOUT_MINUTES` | `1440` (24 hours) | Timeout length for every automatic action. Maximum `40320` (28 days, the Discord limit). |

### Protections

Each protection times out the author, deletes the message, and posts an alert.

| Variable | Default | What it catches |
| --- | --- | --- |
| `ANTI_RAID_ENABLED` | `true` | One user posting the same message in several channels within a short time. All copies are deleted. |
| `ANTI_RAID_LEVEL` | `medium` | `high`: 3 or more channels within 2 minutes. `medium`: 4 or more within 1 minute. `low`: every text channel within 1 minute. |
| `SPAM_MESSAGES_ENABLED` | `true` | Messages containing a phrase from `spam-messages.json` (ignoring case, accents, and spacing), porn-related wording from `spam-description-patterns.json` (the word "NSFW" on its own is allowed), and any message from a user ID in `spam-users.json`. |
| `BLOCKED_LINKS_ENABLED` | `true` | Links to the scam sites in `blocked-domains.json` and a few specific scam URLs, in message text or inside images. |
| `MALICIOUS_INVITES_ENABLED` | `true` | Discord invites, in text or inside images, that lead to a server listed in `malicious-servers.json`. |
| `NSFW_INVITES_ENABLED` | `true` | Invites to servers Discord marks as age-restricted, or whose name, description, or tag contains a keyword from `nsfw-server-keywords.json`. |
| `TEXT_SCAM_ENABLED` | `true` | Hiring and recruitment ads. See [Hiring ads](#hiring-ads). |

### Image scanning

The bot checks every attached or embedded image, including forwarded ones. It
first compares the image with the known scam images in `visual-references/`,
then reads its text with OCR.

| Variable | Default | What it does |
| --- | --- | --- |
| `IMAGE_SCAN_SENSITIVITY` | `high` | How much scam text the OCR must find. `low`: only blocked links or invites. `medium`: "Withdrawal", "Success", and "USDT". `high`: "Withdrawal" and either "Success" or "USDT". `extreme`: any one word such as "money", "bonus", or "casino" (too aggressive for most servers). Known scam images match at every level. |
| `VISUAL_MATCH_THRESHOLD` | `6` | How closely an image must match a known scam image: how many of 64 fingerprint points may differ. Lower is stricter; `0` means near-identical. |
| `MAX_IMAGE_SIZE_MB` | `8` | Larger images are skipped, not scanned. |
| `MAX_IMAGE_PIXELS` | `16000000` | Images with more pixels are skipped. This protects the host from oversized image files. |
| `IMAGE_DOWNLOAD_TIMEOUT_MS` | `15000` | Gives up downloading an image after this many milliseconds. |

### !spamreport command

Off by default. When on, a member with the Manage Messages permission can reply
`!spamreport` to a message. The bot then times out its author, deletes it, and
deletes identical messages from the same author in every channel within the
lookback window. It replies with the result and deletes the command message.

| Variable | Default | What it does |
| --- | --- | --- |
| `SPAM_REPORT_ENABLED` | `false` | Turns the command on. |
| `SPAM_REPORT_TIMEOUT_MINUTES` | `10` | Timeout length for reported users. |
| `SPAM_REPORT_LOOKBACK_MINUTES` | `60` | How far back to look for identical messages. Each 100 messages scanned per channel costs one Discord API request, so keep this short. |

## Hiring ads

`TEXT_SCAM_ENABLED` flags a message only when it contains all three of:

1. **Recruitment intent:** "hiring", "recruiting", "looking for a developer"
   (or engineer, designer, team members, co-founder), "join our team",
   "paid role", "long-term project", "job opportunity", and similar.
2. **A tech role or stack:** developer, engineer, AI, React, backend,
   blockchain, and similar.
3. **A contact request:** DM, message me, contact me, Telegram, WhatsApp,
   portfolio, LinkedIn, CV.

Plain "looking for" and "join" do not count as intent, so help requests such as
"I'm looking for help with my React auth flow, can someone DM me?" and event
invites such as "Join us for the hackathon, DM me" are not flagged. A post
looking for hackathon team members with a contact request is flagged.

The rule lives in `src/detection.js`. The cases it must and must not flag are
in `test/detection.test.js`.

## Good to know

- **The bot never bans or kicks.** The worst it does is a timeout, which a
  moderator can remove (right-click the member, then **Remove Timeout**), and
  deleting the message.
- **Deleted images are not kept.** Alerts include the message text and the
  text read from the image, not the image itself.
- **Quoting spam counts as spam.** A member who pastes a scam message or link
  to ask "is this a scam?" is timed out like the spammer.
- **Forum posts and new threads can be deleted whole.** If a message that
  starts a thread or forum post matches, or its author posts a matching message
  in their own thread within 10 minutes of creating it, the bot deletes the
  whole thread, including other members' replies.
- **Keep `MODERATE_BOTS=false` if another bot logs deleted messages.** With it
  on, the bot deletes the logging bot's copies of spam.
- **It only acts on new and edited messages.** It does not clean up old
  messages, and it cannot see direct messages.
- **Image floods are handled in order.** Images matching a known scam image
  are removed right away. New images are read one at a time, about 0.3 seconds
  each, so in a large image raid removal can lag behind by a minute or more.
- **Alerts never ping anyone**, and the bot only posts in the moderation and
  feedback channels (plus `!spamreport` replies, when enabled).
- **Feedback buttons expire after 15 minutes.** The feedback copy re-downloads
  the images from the deleted message, so it can fail if Discord has already
  removed them.

## Updating the lists

The lists are JSON files in the repository root. Edit them in a pull request,
merge it, then run `/opt/spam-guard-bot/scripts/update.sh` on the server.

| File | Contents |
| --- | --- |
| `blocked-domains.json` | Scam domains. |
| `spam-messages.json` | Exact spam phrases. Multi-line messages can be pasted as-is. |
| `spam-description-patterns.json` | Regular expressions for porn-related wording, such as "porn", "hentai", "OnlyFans", "nudes", and "sex video". Avoid patterns for words developers use, such as a bare "xxx" (a common placeholder) or "sex" (a common schema field). |
| `spam-users.json` | User IDs whose every message is removed. |
| `malicious-servers.json` | Server IDs whose invites are removed. |
| `nsfw-server-keywords.json` | Keywords that mark an invited server as NSFW. |
| `scam-image-channels.json` | Channel IDs known to host scam images. Images whose Discord URL points to one are removed without scanning. |
| `visual-references/` | Known scam images. The bot fingerprints them each time it starts. |

## Tests

```bash
pnpm test
```

## Credits

Based on [spam-guard-bot](https://github.com/DH-555/spam-guard-bot) by David,
under the MIT License.
