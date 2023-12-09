/* Google Apps Script to notify on Discord and Pushbullet on Google Form submission */

const PUSHBULLET_URL = 'https://api.pushbullet.com/v2/pushes'
const PUSHBULLET_TOKEN = PropertiesService.getScriptProperties().getProperty('PUSHBULLET_TOKEN');

const DISCORD_WEBHOOK = PropertiesService.getScriptProperties().getProperty('DISCORD_WEBHOOK');

function onSubmit(event) {
  /* event: authMode, response, source, triggerUid */
  const response_pb = UrlFetchApp.fetch(PUSHBULLET_URL, {
    method: 'POST',
    headers: {
      'Access-Token': PUSHBULLET_TOKEN,
      'Content-Type': 'application/json'
    },
    payload: JSON.stringify({
      title: 'Potluck Challenge Submission',
      body: 'A new challenge has been submitted for the Potluck CTF',
      type: 'note'
    })
  });
  console.log(response_pb.getContentText());

  const response_discord = UrlFetchApp.fetch(DISCORD_WEBHOOK, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    payload: JSON.stringify({
     "username": "Challenge Submission",
      "content": "A new challenge has been submitted to the Potluck CTF"
    })
  });
  console.log(response_discord.getContentText());
}

function testOnSubmit() {
  onSubmit();
}

/*function createOnSubmitTrigger() {
  var form = FormApp.getActiveForm();
  ScriptApp.newTrigger('onSubmit')
      .forForm(form)
      .onFormSubmit()
      .create();
}*/
