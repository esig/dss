function detectBrowserVersion() {
    var userAgent = navigator.userAgent.toLowerCase();
    jQuery.browser = {};
    jQuery.browser.chrome = /chrome/.test(navigator.userAgent.toLowerCase());
    jQuery.browser.mozilla = /mozilla/.test(navigator.userAgent.toLowerCase()) && !/webkit/.test(navigator.userAgent.toLowerCase());
    jQuery.browser.webkit = /webkit/.test(navigator.userAgent.toLowerCase());
    jQuery.browser.opera = /opera/.test(navigator.userAgent.toLowerCase());
    jQuery.browser.msie = /msie/.test(navigator.userAgent.toLowerCase());
    var version = 0;

    // Is this a version of IE?
    if (jQuery.browser.msie) {
        userAgent = jQuery.browser.version;
        userAgent = userAgent.substring(0, userAgent.indexOf('.'));
        version = userAgent;
    }

    // Is this a version of Chrome?
    if (jQuery.browser.chrome) {
        userAgent = userAgent.substring(userAgent.indexOf('chrome/') + 7);
        userAgent = userAgent.substring(0, userAgent.indexOf('.'));
        version = userAgent;
        // If it is chrome then jQuery thinks it's safari so we have to tell it it isn't
        jQuery.browser.safari = false;
    }

    // Is this a version of Safari?
    if (jQuery.browser.safari) {
        userAgent = userAgent.substring(userAgent.indexOf('safari/') + 7);
        userAgent = userAgent.substring(0, userAgent.indexOf('.'));
        version = userAgent;
    }

    // Is this a version of Mozilla?
    if (jQuery.browser.mozilla) {
        //Is it Firefox?
        if (navigator.userAgent.toLowerCase().indexOf('firefox') != -1) {
            userAgent = userAgent.substring(userAgent.indexOf('firefox/') + 8);
            userAgent = userAgent.substring(0, userAgent.indexOf('.'));
            version = userAgent;
        }
        // If not then it must be another Mozilla
        else {
        }
    }

    // Is this a version of Opera?
    if (jQuery.browser.opera) {
        userAgent = userAgent.substring(userAgent.indexOf('version/') + 8);
        userAgent = userAgent.substring(0, userAgent.indexOf('.'));
        version = userAgent;
    }
    return version;
}
