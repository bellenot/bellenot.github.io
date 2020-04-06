// ***
// *** The following code is Copyright (c) 2002, Marc Richarme ***
// ***
// *** devix@devix.cjb.net
// *** http://devix.cjb.net
// ***
//
// This code may be use freely, free of any charge, by anyone
// and for any purpose.
// Don't claim you made it, and if you modify it and plan to
// redistribute a modified version, it must be stated clearly
// in the source files that it's not the original file.
//
// This code is provided AS IS. I don't guarantee it works
// and I certainly don't guarantee it's secure!
// Tested on Internet Explorer 6.
//
// Parts of the code are Copyright (C) Paul Johnston 1999 - 2002.
//



//********************************************************************
//** Start of interface classes.
//********************************************************************

// Global vars
var __UserArray = new Array();	// associative array used for basic login checking
var __Location = new LocationArray(); // associative array describing the querystring

// DeclareUser('hashed_name', 'hashed_password', [AdminGroup,'encrypted_admin_master'], [Group1,'encrypted_master_1'], ...);

function DeclareUser(hashed_user_name, hashed_password)
{
  if(arguments.length < 3) return false;
  for(i = 2; i < arguments.length; i++)
  {
//    if(arguments[i][0].constructor != Group) return false; // sanity check
//    if(arguments[i][1].constructor != String) return false; // sanity check
    arguments[i][0].Add(new User(hashed_user_name,arguments[i][1]));
  }
  if(typeof(__UserArray[hashed_user_name]) != 'undefined')
    alert('Warning:\n\nThe following user has been defined more than once: " '+hashed_user_name+' ".\nThis will probably lead to problems, dependings on what functions you are using.\n\nIf you are the webmaster of this webpage, you should fix this asap,\notherwise you should contact the webmaster and inform him of this problem.');
  else
    __UserArray[hashed_user_name] = hashed_password;
  return true;
}

// DeclarePassword([Group0,'encrypted_master_0'], [Group1,'encrypted_master_1'], ...);

function DeclarePassword()
{
  if(arguments.length < 1) return false;
  for(i = 0; i < arguments.length; i++)
  {
//    if(arguments[i][0].constructor != Group) return false; // sanity check
//    if(arguments[i][1].constructor != String) return false; // sanity check
    arguments[i][0].Add(new Password(hashed_user_name,arguments[i][1]));
  }
  return true;
}

function LocationArray()
{
  this.length = 0;
  var s = location.search;
  if(s.charAt(0) == '?') s = s.substr(1);
  var ar = s.split('&');
  var n,key;
  for(i = 0; i < ar.length; i++)
  {
    n = ar[i].indexOf('=');
    if(n != -1)
    {
      this[ar[i].substr(0,n)] = ar[i].substr(n+1);
      this.length++;
    }
  }
}


// Interface classes

function Password(encrypted_master_password)
{
  this.emp = encrypted_master_password;
  this.DecryptMaster = __DecryptMaster;
}

function User(hashed_user_name,encrypted_master_password)
{
  this.name = hashed_user_name;
  this.emp = encrypted_master_password;
  this.DecryptMaster = __DecryptMaster;
}

function Group(hashed_master_password)
{
  this.length = 0;
  this.hmp = hashed_master_password;
  this.CheckMaster = __CheckMaster;	// bool *(string master)
  this.GetMaster = __GetMaster;	// string *(string user, string password)
  this.Verify = new Function('user','password','return new Boolean(this.GetMaster(user,password))');	// bool *(string user, string password)
  this.Add = __Add;	// int *(object obj)
}

function Resource(group,content)
{
  this.group = group;
  this.content = content;
  this.DecryptResourceM = __DecryptResourceM;
  this.DecryptResourceUP = __DecryptResourceUP;
  this.DecryptResourceS = __DecryptResourceS;
  this.DecryptFromLocation = __DecryptFromLocation;
  
  this.Callback = null;
  this.MakeCallbackCall = __MakeCallbackCall;
  
}

function Session(cookie_base)
{
  this.bIsLoggedIn = false;
  this.bUseCookies = new Boolean(cookie_base);
  this.sUserNameCookie = cookie_base ? "" + cookie_base + "_name" : null;
  this.sPasswordCookie = cookie_base ? "" + cookie_base + "_pass" : null;
  this.nCookieExpirationDelay = 1; // specified in hours. null = session-only cookie (doesn't seem to work properly)
  this.bLocationLogin = false;
  this.sUserName = null;
  this.sPassword = null;
  this.Login = __Login;
  this.Logout = __Logout;
  this.UserLogin = __UserLogin;
  this.DeleteLoginInfo = __DeleteLoginInfo;
  this.SaveLoginInfo = __SaveLoginInfo;
  this.RestoreLoginInfo = __RestoreLoginInfo;
  this.Init = __Init;
  this.LoginFromLocation = __LoginFromLocation;

  this.Callback = null;
  this.MakeCallbackCall = __MakeCallbackCall;
}

// Static members

Session.prototype.ccLogin = 1;	// lparam = [user,password]
Session.prototype.ccLogout = 2;	// lparam = null
Resource.prototype.ccBeforeDecrypt = 1;	// lparam = plaintext master password
Resource.prototype.ccAfterDecrypt = 2;	// lparam = plaintext content
Resource.prototype.ccInvallidMaster = 3;

// Member functions

function __Init()
{
  if(this.bLocationLogin)
    this.LoginFromLocation();
  if(!this.bIsLoggedIn && this.bUseCookies)
    this.RestoreLoginInfo();
}

function __MakeCallbackCall(context,lparam)
{
  if(typeof(this.Callback) != 'function')
    return true;
  return this.Callback(context,lparam);
}

function __UserLogin(user,password,use_cookies)
{
  var old_use_cookies = this.bUseCookies;
  if(!use_cookies) this.bUseCookies = false;
  var bRet = this.Login(user,password);
  this.bUseCookies = old_use_cookies;
  if(!bRet) alert('Invallid username or password!');
  return bRet;
}

function __Login(user,password)
{
  if(this.bIsLoggedIn) Logout();
  var hashed_user = b64MD5(user);
  if(typeof(__UserArray[hashed_user]) != 'string') return false; // invallid user?
  if(__UserArray[hashed_user] != b64MD5(password)) return false; // invallid password?
  this.sUserName = user;
  this.sPassword = password;
  this.bIsLoggedIn = true;
  if(this.bUseCookies)
    this.SaveLoginInfo();
  if(!this.MakeCallbackCall(this.ccLogin,[user,password]))
    this.Logout();
  return true;
}

function __Logout()
{
  this.DeleteLoginInfo(); // note: delete cookie even if this.bUseCookies is false!
  this.sUserName = null;
  this.sPassword = null;
  this.bIsLoggedIn = false;
  this.MakeCallbackCall(this.ccLogout,null);
}

// wrappers around cookie handling

function __SaveLoginInfo()
{
  if(!this.bIsLoggedIn)
    return false;
  // We store the username and password as a cookie on the users machine.
  // Password is not stored as plaintext but encrypted with the username.
  // Obviously, this is *in no way secure* but *theoretically* no one but us
  // should be able to read the cookie without physical access to the computer.
  var enc_pass = rc4(this.sUserName,this.sPassword); // textToBase64 is done in setCookie
  var today = new Date();
  var exp = this.nCookieExpirationDelay ? (new Date(today.getTime()+3600000*this.nCookieExpirationDelay)) : null;
  setCookie(this.sUserNameCookie,this.sUserName,exp);
  setCookie(this.sPasswordCookie,enc_pass,exp);
  return true;
}

function __RestoreLoginInfo()
{
  if(this.bIsLoggedIn)
    this.Logout();
  var user = getCookie(this.sUserNameCookie);
  var pass = getCookie(this.sPasswordCookie);
  if(!user || !pass)
    return false;
  pass = rc4(user,pass); // base64ToText is done in getCookie
  return this.Login(user,pass);
}

function __DeleteLoginInfo()
{
  delCookie(this.sUserNameCookie);
  delCookie(this.sPasswordCookie);
  return true;
}

function __DecryptResourceS(session)
{
  if(!session || !session.bIsLoggedIn || !session.sUserName || !session.sPassword)
    return false;
  return this.DecryptResourceUP(session.sUserName,session.sPassword);
}

function __DecryptResourceUP(user,password)
{
  master = this.group.GetMaster(user,password);
  return this.DecryptResourceM(master);
}

function __DecryptResourceM(master)
{
  if(!master)
  {
    this.MakeCallbackCall(this.ccInvallidMaster,master)
    return false;
  }
  if(!this.MakeCallbackCall(this.ccBeforeDecrypt,master))
    return false;
  var ret = rc4(master,base64ToText(this.content));
  if(!this.MakeCallbackCall(this.ccAfterDecrypt,ret))
    return false;
  return ret;
}

function __DecryptFromLocation()
{
  if(typeof(__Location['pass']) != 'string')
    return false;
  if(typeof(__Location['user']) == 'string')
    return this.DecryptResourceUP(__Location['user'],__Location['pass']);
  else
    return this.DecryptResourceUP('',__Location['pass']);
}

function __DecryptMaster(password)
{
  return rc4(password,base64ToText(this.emp));
}

function __CheckMaster(master)
{
  return (b64MD5(master) == this.hmp);
}

function __GetMaster(user,password)
{
  var master;
  if(user != '')
  {
    user = b64MD5(user);
    for(i = 0; i < this.length; i++)
    {
      if(this[i].constructor == User && this[i].name == user)
      {
      	master = this[i].DecryptMaster(password);
        if(this.CheckMaster(master))
          return master;
      }
    }
  }
  else
  {
    for(i = 0; i < this.length; i++)
    {
      if(this[i].constructor == Password)
      {
      	master = this[i].DecryptMaster(password);
        if(this.CheckMaster(master))
          return master;
      }
    }
  }
  return null;
}

function __Add(obj)
{
  this[this.length] = obj;
  return this.length++;
}

function __LoginFromLocation()
{
  if((typeof(__Location['pass']) != 'string') ||
    (typeof(__Location['user']) != 'string'))
    return false;

  var old_use_cookies = this.bUseCookies;
  this.bUseCookies = false;
  var bRet = this.Login(__Location['user'],__Location['pass']);
  this.bUseCookies = old_use_cookies;
  return bRet;
}

//
//********************************************************************
//** End of interface.
//** You shouldn't need to explicitly call the below functions
//********************************************************************
//

////////////////////////////////////////////////////////////////////
// Misc Functions
var hex_tab = "0123456789abcdef"
var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

function char2hex(i) {
  return ("" + tab.charAt(i >> 4) + tab.charAt(i & 0xF));
}

//function word2hex(i)
//{ return binl2hex([i]); }

function bin2asc(data)
{
  var output = "";
  for(i = 0; i < data.length; i++)
    output += int2hex(data.charCodeAt(i));
  return output;
}

function asc2bin(data)
{
  var output = "";
  for(i = 0; i < data.length; i+=2)
    output += String.fromCharCode(parseInt(data.substr(i,2),16));
  return output;
}

// Convert an array of little-endian words to a hex string.
function binl2hex(binarray)
{
  var str = ""
  for(var i = 0; i < binarray.length * 4; i++)
  {
    str += hex_tab.charAt((binarray[i>>2] >> ((i%4)*8+4)) & 0xF) +
           hex_tab.charAt((binarray[i>>2] >> ((i%4)*8)) & 0xF)
  }
  return str
}

// Convert an array of little-endian words to a base64 encoded string.
function binl2b64(binarray)
{
  var str = ""
  for(var i = 0; i < binarray.length * 32; i += 6)
  {
    str += tab.charAt(((binarray[i>>5] << (i%32)) & 0x3F) |
                      ((binarray[i>>5+1] >> (32-i%32)) & 0x3F))
  }
  return str
}

// Convert an 8-bit character string to a sequence of 16-word blocks, stored
// as an array, and append appropriate padding for MD4/5 calculation.
// If any of the characters are >255, the high byte is silently ignored.
function str2binl(str)
{
  var nblk = ((str.length + 8) >> 6) + 1 // number of 16-word blocks
  var blks = new Array(nblk * 16)
  for(var i = 0; i < nblk * 16; i++) blks[i] = 0
  for(var i = 0; i < str.length; i++)
    blks[i>>2] |= (str.charCodeAt(i) & 0xFF) << ((i%4) * 8)
  blks[i>>2] |= 0x80 << ((i%4) * 8)
  blks[nblk*16-2] = str.length * 8
  return blks
}

// Convert a wide-character string to a sequence of 16-word blocks, stored as
// an array, and append appropriate padding for MD4/5 calculation.
function strw2binl(str)
{
  var nblk = ((str.length + 4) >> 5) + 1 // number of 16-word blocks
  var blks = new Array(nblk * 16)
  for(var i = 0; i < nblk * 16; i++) blks[i] = 0
  for(var i = 0; i < str.length; i++)
    blks[i>>1] |= str.charCodeAt(i) << ((i%2) * 16)
  blks[i>>1] |= 0x80 << ((i%2) * 16)
  blks[nblk*16-2] = str.length * 16
  return blks
}


function textToBase64(t) {
 var r=''; var m=0; var a=0; var tl=t.length-1; var c
 for(n=0; n<=tl; n++) {
  c=t.charCodeAt(n)
  r+=tab.charAt((c << m | a) & 63)
  a = c >> (6-m)
  m+=2
  if(m==6 || n==tl) {
   r+=tab.charAt(a)
//   if((n%45)==44) {r+="\n"}
   m=0
   a=0
  }
 }
 return r
}
function base64ToText(t) {
 var r=''; var m=0; var a=0; var c
 for(n=0; n<t.length; n++) {
  c=tab.indexOf(t.charAt(n))
  if(c >= 0) {
   if(m) {
    r+=String.fromCharCode((c << (8-m))&255 | a)
   }
   a = c >> m
   m+=2
   if(m==8) { m=0 }
  }
 }
 return r
}


// RC4 stream encryption
// adapted from www.cpan.org crypt::rc4 -- thanks!
function rc4(key, text) {
 var i, x, y, t, x2, kl=key.length;
 s=[];

 for (i=0; i<256; i++) s[i]=i
 y=0
 x=kl; while(x--) {
  y=(key.charCodeAt(x) + s[x] + y) % 256
  t=s[x]; s[x]=s[y]; s[y]=t
 }
 x=0;  y=0;
 var z=""
 for (x=0; x<text.length; x++) {
  x2=x & 255
  y=( s[x2] + y) & 255
  t=s[x2]; s[x2]=s[y]; s[y]=t
  z+= String.fromCharCode((text.charCodeAt(x) ^ s[(s[x2] + s[y]) % 256]))
 }
 return z
}

////////////////////////////////////////////////////////////////////
// Cookie Functions
function setCookie(name, value, expires)
{
  document.cookie = 
    name + "=" + textToBase64(value) + "; expires=" +
    (expires ? expires.toGMTString() : "") +
    "; path=/";
}

function getCookie(name)
{
  var dcookie = document.cookie; 
  var cname = name + "=";
  var clen = dcookie.length;
  var cbegin = 0;
  while (cbegin < clen)
  {
    var vbegin = cbegin + cname.length;
    if (dcookie.substring(cbegin, vbegin) == cname)
    { 
      var vend = dcookie.indexOf (";", vbegin);
      if (vend == -1) vend = clen;
      return base64ToText(dcookie.substring(vbegin, vend));
    }
    cbegin = dcookie.indexOf(" ", cbegin) + 1;
    if(cbegin == 0) break;
  }
  return null;
}

function delCookie(name)
{
  document.cookie = name + "=; expires=Thu, 01-Jan-70 00:00:01 GMT; path=/";
}


////////////////////////////////////////////////////////////////////
// MD5 Hash Algorithm
//
// Copyright notice for the MD5 source:
///////////////////////////////////////
// A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
// Digest Algorithm, as defined in RFC 1321.
// Version 1.1 Copyright (C) Paul Johnston 1999 - 2002.
// Code also contributed by Greg Holt
// See http://pajhome.org.uk/site/legal.html for details.
///////////////////////////////////////
// This version has probably been modified to suit the needs of
// this package... for the original source, visit the bove url.



// Add integers, wrapping at 2^32. This uses 16-bit operations internally
// to work around bugs in some JS interpreters.
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF)
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16)
  return (msw << 16) | (lsw & 0xFFFF)
}

// Bitwise rotate a 32-bit number to the left.
function rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt))
}

// These functions implement the four basic operations the algorithm uses.
function cmn(q, a, b, x, s, t)
{
  return safe_add(rol(safe_add(safe_add(a, q), safe_add(x, t)), s), b)
}
function ff(a, b, c, d, x, s, t)
{
  return cmn((b & c) | ((~b) & d), a, b, x, s, t)
}
function gg(a, b, c, d, x, s, t)
{
  return cmn((b & d) | (c & (~d)), a, b, x, s, t)
}
function hh(a, b, c, d, x, s, t)
{
  return cmn(b ^ c ^ d, a, b, x, s, t)
}
function ii(a, b, c, d, x, s, t)
{
  return cmn(c ^ (b | (~d)), a, b, x, s, t)
}

// Calculate the MD5 of an array of little-endian words, producing an array
// of little-endian words.
function coreMD5(x)
{
  var a =  1732584193
  var b = -271733879
  var c = -1732584194
  var d =  271733878

  for(i = 0; i < x.length; i += 16)
  {
    var olda = a
    var oldb = b
    var oldc = c
    var oldd = d

    a = ff(a, b, c, d, x[i+ 0], 7 , -680876936)
    d = ff(d, a, b, c, x[i+ 1], 12, -389564586)
    c = ff(c, d, a, b, x[i+ 2], 17,  606105819)
    b = ff(b, c, d, a, x[i+ 3], 22, -1044525330)
    a = ff(a, b, c, d, x[i+ 4], 7 , -176418897)
    d = ff(d, a, b, c, x[i+ 5], 12,  1200080426)
    c = ff(c, d, a, b, x[i+ 6], 17, -1473231341)
    b = ff(b, c, d, a, x[i+ 7], 22, -45705983)
    a = ff(a, b, c, d, x[i+ 8], 7 ,  1770035416)
    d = ff(d, a, b, c, x[i+ 9], 12, -1958414417)
    c = ff(c, d, a, b, x[i+10], 17, -42063)
    b = ff(b, c, d, a, x[i+11], 22, -1990404162)
    a = ff(a, b, c, d, x[i+12], 7 ,  1804603682)
    d = ff(d, a, b, c, x[i+13], 12, -40341101)
    c = ff(c, d, a, b, x[i+14], 17, -1502002290)
    b = ff(b, c, d, a, x[i+15], 22,  1236535329)

    a = gg(a, b, c, d, x[i+ 1], 5 , -165796510)
    d = gg(d, a, b, c, x[i+ 6], 9 , -1069501632)
    c = gg(c, d, a, b, x[i+11], 14,  643717713)
    b = gg(b, c, d, a, x[i+ 0], 20, -373897302)
    a = gg(a, b, c, d, x[i+ 5], 5 , -701558691)
    d = gg(d, a, b, c, x[i+10], 9 ,  38016083)
    c = gg(c, d, a, b, x[i+15], 14, -660478335)
    b = gg(b, c, d, a, x[i+ 4], 20, -405537848)
    a = gg(a, b, c, d, x[i+ 9], 5 ,  568446438)
    d = gg(d, a, b, c, x[i+14], 9 , -1019803690)
    c = gg(c, d, a, b, x[i+ 3], 14, -187363961)
    b = gg(b, c, d, a, x[i+ 8], 20,  1163531501)
    a = gg(a, b, c, d, x[i+13], 5 , -1444681467)
    d = gg(d, a, b, c, x[i+ 2], 9 , -51403784)
    c = gg(c, d, a, b, x[i+ 7], 14,  1735328473)
    b = gg(b, c, d, a, x[i+12], 20, -1926607734)

    a = hh(a, b, c, d, x[i+ 5], 4 , -378558)
    d = hh(d, a, b, c, x[i+ 8], 11, -2022574463)
    c = hh(c, d, a, b, x[i+11], 16,  1839030562)
    b = hh(b, c, d, a, x[i+14], 23, -35309556)
    a = hh(a, b, c, d, x[i+ 1], 4 , -1530992060)
    d = hh(d, a, b, c, x[i+ 4], 11,  1272893353)
    c = hh(c, d, a, b, x[i+ 7], 16, -155497632)
    b = hh(b, c, d, a, x[i+10], 23, -1094730640)
    a = hh(a, b, c, d, x[i+13], 4 ,  681279174)
    d = hh(d, a, b, c, x[i+ 0], 11, -358537222)
    c = hh(c, d, a, b, x[i+ 3], 16, -722521979)
    b = hh(b, c, d, a, x[i+ 6], 23,  76029189)
    a = hh(a, b, c, d, x[i+ 9], 4 , -640364487)
    d = hh(d, a, b, c, x[i+12], 11, -421815835)
    c = hh(c, d, a, b, x[i+15], 16,  530742520)
    b = hh(b, c, d, a, x[i+ 2], 23, -995338651)

    a = ii(a, b, c, d, x[i+ 0], 6 , -198630844)
    d = ii(d, a, b, c, x[i+ 7], 10,  1126891415)
    c = ii(c, d, a, b, x[i+14], 15, -1416354905)
    b = ii(b, c, d, a, x[i+ 5], 21, -57434055)
    a = ii(a, b, c, d, x[i+12], 6 ,  1700485571)
    d = ii(d, a, b, c, x[i+ 3], 10, -1894986606)
    c = ii(c, d, a, b, x[i+10], 15, -1051523)
    b = ii(b, c, d, a, x[i+ 1], 21, -2054922799)
    a = ii(a, b, c, d, x[i+ 8], 6 ,  1873313359)
    d = ii(d, a, b, c, x[i+15], 10, -30611744)
    c = ii(c, d, a, b, x[i+ 6], 15, -1560198380)
    b = ii(b, c, d, a, x[i+13], 21,  1309151649)
    a = ii(a, b, c, d, x[i+ 4], 6 , -145523070)
    d = ii(d, a, b, c, x[i+11], 10, -1120210379)
    c = ii(c, d, a, b, x[i+ 2], 15,  718787259)
    b = ii(b, c, d, a, x[i+ 9], 21, -343485551)

    a = safe_add(a, olda)
    b = safe_add(b, oldb)
    c = safe_add(c, oldc)
    d = safe_add(d, oldd)
  }
  return [a, b, c, d]
}

// MD5 External interface
function hexMD5 (str) { return binl2hex(coreMD5( str2binl(str))) }
function hexMD5w(str) { return binl2hex(coreMD5(strw2binl(str))) }
function b64MD5 (str) { return binl2b64(coreMD5( str2binl(str))) }
function b64MD5w(str) { return binl2b64(coreMD5(strw2binl(str))) }