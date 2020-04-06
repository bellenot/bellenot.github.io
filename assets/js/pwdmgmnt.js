

function getCookieVal (offset) {
   var endstr = document.cookie.indexOf (";", offset);
   if (endstr == -1)
   endstr = document.cookie.length;
   return unescape(document.cookie.substring(offset, endstr));
}

function GetCookie (name)  {
   var arg = name + "=";
   var alen = arg.length;
   var clen = document.cookie.length;
   var i = 0;
   while (i < clen)  {
      var j = i + alen;
      if (document.cookie.substring(i, j) == arg)
         return getCookieVal (j);i = document.cookie.indexOf(" ", i) + 1;
      if (i == 0) break;
   }
   return null;
}

function SetCookie (name, value)  {
   var argv = SetCookie.arguments;
   var argc = SetCookie.arguments.length;
   var expires = (argc > 2) ? argv[2] : null;
   var path = (argc > 3) ? argv[3] : null;
   var domain = (argc > 4) ? argv[4] : null;
   var secure = (argc > 5) ? argv[5] : false;
   document.cookie = name + "=" + escape (value) +
      ((expires == null) ? "" : ("; expires=" + expires.toGMTString())) +
      ((path == null) ? "" : ("; path=" + path)) +
      ((domain == null) ? "" : ("; domain=" + domain)) +
      ((secure == true) ? "; secure" : "");
}

function DeleteCookie () {
   var exp = new Date();
   exp.setTime (exp.getTime() - 1000000000);  // This cookie is history
   var cval = GetCookie ('ProtectedStuffL');
   document.cookie ='ProtectedStuffL' + "=" + cval + "; expires=" + exp.toGMTString();
}

function cookieCreater (url) {
   if (GetCookie('ProtectedStuffL') == null) {
      var ProtectedStuffL_Name =  prompt ("What name do you want to go by? (your first name)\n\nQuel nom voulez-vous utiliser ? (votre pr\351nom)", "" );
      if (ProtectedStuffL_Name != null && ProtectedStuffL_Name != "") {
         var expdate = new Date ();
         //expdate.setTime(expdate.getTime() + (24 * 60 * 60 * 1000 * 365)); // one year !
         //expdate.setTime(expdate.getTime() + (24 * 60 * 60 * 1000 * 7)); // one week
         expdate.setTime(expdate.getTime() + (24 * 60 * 60 * 1000)); // one day
         SetCookie('ProtectedStuffL', ProtectedStuffL_Name, expdate);
         alert ("Hello " + ProtectedStuffL_Name + ", you now are logged in!  From now on, when you come to this page, you will be forwarded to the Password Protected Area.  Please do not tell anyone your entry code.  Have fun!"+
                "\n\nBonjour " + ProtectedStuffL_Name + ", vous \352tes maintenant authentifi\351(e)!  A partir de maintenant, quand vous acc\351derez \340 cette page, vous serez redirig\351(e) sur la page prot\351g\351e par mot de passe.  Veuillez ne pas divulguer votre mot de passe. Amusez-vous bien!");
         location.href = url;
      }
   }
   else {
      DeleteCookie ();
      cookieCreater ()
   }
}
