/**
* GAS library for generating user OAuth Tokens via Google service account. see 
* @param {String} rsaKey The private_key from your service account JSON key
* @param {Array} Scopes An Array of scopes you want to authenticate
* @param {String} saEmail The service account Email
* @return {object} self for chaining
*/
function init(rsaKey, Scopes, saEmail){
  var self = this;
  var rsaKey_ = rsaKey;
  var Scopes_ = Scopes;
  var saEmail_ = saEmail;
  var jwts_ ;
  var tokens_ = {};
  var expireTime_;
  var subAccounts_;
  
  
  if (!rsaKey_) {
    throw 'You must provide the private key';
  }
  if(!(Scopes_.constructor === Array)){
    throw "The Scopes must be in a valid array"
  }
  
  if (!Scopes_) {
    throw 'You must provide atleast one scope';
  }
  
  if (!saEmail_) {
    throw 'You must provide the service account email';
  }
  
  self.addUser = function(userEmail){
    if(!subAccounts_)subAccounts_ = [];
    subAccounts_.push(userEmail);
    return self;
  }
  
  self.addUsers = function(userEmailArray){
    if(!subAccounts_)subAccounts_ = [];
    subAccounts_ =  Array.concat(subAccounts_,userEmailArray);
    return self;
  }
  
  self.removeUsers = function(){
    subAccounts_ = null;
    return self;
  }
  
  self.removeUser = function(userEmail){
    var index = subAccounts_.indexOf(userEmail);
    if (index > -1) {
      subAccounts_.splice(index, 1);
    }
    return self;
  }
  
  self.generateJWT_ = function(){
    var sResult="",claim="";
    
    if(!subAccounts_){
      throw new Error("You must add at least one user account");
    }
    var sPayloads = [];
    var header = Utilities.base64Encode('{"alg":"RS256","typ":"JWT"}');
    
    for(var i=0; i<subAccounts_.length; i++){
      sPayloads.push({"claim":header+"."+Utilities.base64Encode(JSON.stringify(makeClaim(subAccounts_[i]))),"user":subAccounts_[i],"expire":expireTime_});
    } 
    
    
    try {
      var JWTs = {};
      
      for(var i=0; i < sPayloads.length; i++){
        
        JWTs[sPayloads[i].user]={"signedClaim": sPayloads[i].claim +"."+ Utilities.base64Encode(Utilities.computeRsaSha256Signature(sPayloads[i].claim, rsaKey_)),
                                 "expire":sPayloads[i].expire};
      }
      jwts_ = JWTs;
      
    } catch (ex) {
      throw new Error("Error generating JWT: " + ex);
    }
    return self;
  } 
  
  self.getToken = function(userEmail){
    if(!(userEmail in tokens_)){
      throw new Error("User not found");    
    }else{
      return tokens_[userEmail];
    }
  }
  
  self.getTokens = function(){
    return tokens_;
  }
  
  
  
  
  self.requestToken = function(){
    self.generateJWT_();
    if(!jwts_){
      throw 'You must run generateJWT'
    }
    
    var params = {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: ''
    }
    
    
    var url = "https://www.googleapis.com/oauth2/v3/token"
    var parameters = { 'method' : 'post',                    
                      'payload' : params,
                      muteHttpExceptions:true};
    
    var response="";
    
    for(var user in jwts_){
      params.assertion = jwts_[user].signedClaim;
      response = JSON.parse(UrlFetchApp.fetch(url,parameters).getContentText());
      
      if(response.error){
        if(response.error === "invalid_grant"){
          tokens_[user]={};
          tokens_[user].token = "invalid_grant: Does this user exist?";
          tokens_[user].expire = jwts_[user].expire;
        }else{
          throw new Error('There was an error requesting a Token from the OAuth server: '+ response.error);
        }
      }
      
      if(response.access_token)
      {
        tokens_[user]={};
        tokens_[user].token = response.access_token;
        tokens_[user].expire = jwts_[user].expire;
      }
    }
    return self;
  }
  function makeClaim(subAccount){
    var now = (Date.now()/1000).toString().substr(0,10);
    var exp = (parseInt(now) + 3600).toString().substr(0,10);
    expireTime_ = exp;
    var claim = 
        {
          "iss": saEmail_,
          "sub": subAccount,
          "scope": Scopes_.join(" "),
          "aud":"https://www.googleapis.com/oauth2/v3/token",
          "iat": now,
          "exp": exp
        };
    if(subAccount === saEmail_){
      delete claim.sub;
    }
    return claim;
  }
  return self;
}
