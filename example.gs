function example(){
  
  
  var jsonKey = JSON.parse(PropertiesService.getScriptProperties().getProperty("jsonKey"));
  var key = jsonKey.private_key;
  var clientEmail = jsonKey.client_email;
  
  //example how to request OAuth2 tokens of your domain users
  var userTokens = new GSApp.init(key, ['https://www.googleapis.com/auth/drive'], clientEmail);
  userTokens.addUser("1test@example.com")
            .addUser("1test@example.com") //add multiple users to batch process
            .removeUsers()                //remove all users
            .addUser("1test@example.com")
            .addUsers(["2test@example.com","3test@example.com"]) //pass an array of user emails
            .removeUser("1test@example.com")    //remove individual users      
            .removeUser("Fonzie")               // shouldn't break things
            .addUser("doesNotExist@example.com")  //adds an invalid_grant error in the token property
            .requestToken();  //requests the tokens and saves them in GSApp
  Logger.log(userTokens.getTokens()); //returns tokens for all added users
  Logger.log(userTokens.getToken("1test@example.com")); //returns the token for the specified user
  
  //example how to request an Oauth2 token for your script
  var serverToken = new GSApp.init(key, ['https://www.googleapis.com/auth/drive'], clientEmail);
  sb.addUser(clientEmail)
    .requestToken();
  Logger.log(serverToken.getTokens());
  
}
