<?php
/**
 * Helps troubleshoot LDAP connection/authentication issues
 * @version 1.1.0
 */

/**
 * User account you want to use to try authentication on
 */
$strTestUser = 'yourtestuser';
/**
 * User's password
 */
$strTestPass = 'yourtestuserpassword';
/**
 * Items you MUST change
 */
$aryRequired = array(
    //account to use for binding
    'bindaccount'   => 'yourbindaccount',
    //bind account password
    'bindpass'      => 'yourbindaccountpassword',
    // ldap server address
    'ldapserver'   => 'ldap.domain.com',
    //ldap port
    'ldapport'      => 3268,
    //LDAP domain
    'addomain'      => 'domain.com',
    //base dn for searching
    'basedn'        => 'dc=edu',
);

/**
 * Items you /can/ change.  The defaults are shown.  To use, create an array with these keys and pass in as the second
 * parameter upon construction of the LDAP_Test object

$aryOptions = array(
    //should be we use LDAP v3?
    'useldap3'          => true,
    //Use ldaps instead of tls
    'useldaps'          => false,
    // use TLS?
    'starttls'          => true,
    //uid search filter
    'uidfilter'         => 'sAMAccountName=',
    //email filter
    'emailfilter'       => 'proxyAddresses=smtp:',
    // regex pattern for valid uid, negated
    'uidpattern'        => '/[^A-z0-9@.-]+/',
    // regex pattern for passwords, negated
    'passwordpattern'   => '/[^A-z0-9(*&)=?|^}\/_>#:-[\052];]~,\[<.]+/',
    // minimum password length
    'passwordmin'       => 8,
    //maximum password length
    'passwordmax'       => 26,
);
 */
$aryOptions = array();

echo '<h1>Simple LDAP Test</h1>',PHP_EOL,'<p>Trying to authenticate ', $strTestUser,'...</p>',PHP_EOL;

$objMyLdap = new LDAP_Test($aryRequired,$aryOptions);

if($objMyLdap->authSSO($strTestUser,$strTestPass)){
    echo '<p>',$strTestUser,' authenticated successfully!</p>',PHP_EOL;
} else {
    echo '<h2>Authentication failed</h2>',PHP_EOL;
    if ($objMyLdap->wasErrorEncountered()){
        echo '<h3>Problem Encountered While Attempting to Authenticate</h3>',PHP_EOL;
        $objMyLdap->displayErrors();
    } else {
        echo '<p>Failed to authenticate user due to invalid credentials</p>',PHP_EOL;
    }
}

class LDAP_Test {
    private $aryRequiredKeys = array(
        'bindaccount',
        'bindpass',
        'ldapserver',
        'ldapport',
        'addomain',
        'basedn',
    );

    private $aryLDAPParams = null;
    private $aryDefaultOptions = array(
        //should be we use LDAP v3?
        'useldap3'          => true,
        'starttls'          => true,
        'useldaps'          => false,
        'uidfilter'         => 'sAMAccountName=',
        'emailfilter'       => 'proxyAddresses=smtp:',
        'uidpattern'        => '/[^A-z0-9@.-]+/',
        'passwordpattern'   => '/[^A-z0-9(*&)=?|^}\/_>#:-[\052];]~,\[<.]+/',
        'passwordmin'       => 8,
        'passwordmax'       => 26,
    );

    protected $aryOptions = array();

    private $aryErrors = array();

    protected $rscConnection = null;

    protected $strStartTLSErrorMsg = <<<STARTTLS
start_tls failed to start. HOWEVER, this does not necessarily mean that there is a problem with your ssl library. 
Technically, this is the first time the ldap server (%s) has been contacted, so double-check that the server address is 
correct and is currently reachable. If it is, the next common issue is with TLS_REQCERT in ldap.conf. If the name in the 
cert doesn't match the name of the domain controller you connected to (e.g. your ldap server address is a round robin to 
individual domain controllers), start_tls will fail. Another common problem on windows OS is the location of ldap.conf 
and location of your *.crt files.  If you are running into issues, I <strong>HIGHLY</strong> suggest reading through the 
user comments at <a href="http://php.net/manual/en/function.ldap-start-tls.php">http://php.net/manual/en/function.ldap-start-tls.php</a>.';        
STARTTLS;


    protected $strLDAPSearchErrMsg = <<<LDAPSEARCHMSG
problem encountered searching for user %s, using filter <strong>%s</strong> and baseDN <strong>%s</strong>. However, if
the last LDAP error is <em>Operations error</em> and your LDAP instance allows anonymous binds, but not anonymous searches
the problem might actually be with your bind account/password.
LDAPSEARCHMSG;


    /**
     * LDAP_Test constructor.
     * @param array $aryRequired
     * @param array $aryOptions
     * @throws ErrorException
     */
    public function __construct($aryRequired,$aryOptions = array())
    {
        if(!is_array($aryRequired) || 0 != count(array_diff($this->aryRequiredKeys,array_keys($aryRequired)))){
            //we have to have the required pieces
            throw new ErrorException('We need all 5 key - value pairs in order to instantiate LDAP_Test.');
        } else {
            $this->aryLDAPParams = $aryRequired;
        }

        $this->aryOptions = array_merge($this->aryDefaultOptions,$aryOptions);

        if($this->aryOptions['starttls'] && $this->aryOptions['useldaps']){
            throw new ErrorException('You have both starttls and useldaps set to true in the options. I can do one or the other but not both.' );
        }

    }

    /**
     * Attempt to authenticate $strUser against ldap using user email to look up user DN
     * @param string $strEmailAddress
     * @param string $strPassword
     * @return bool
     */
    public function authEmail($strEmailAddress,$strPassword)
    {
        return $this->auth($strEmailAddress,$strPassword,$this->aryOptions['emailfilter']);
    }

    /**
     * Attempt to authenticate $strUser against ldap using ssoid/uid to look up user DN
     * @param string $strUser
     * @param string $strPassword
     * @return bool
     */
    public function authSSO($strUser,$strPassword)
    {
        return $this->auth($strUser,$strPassword,$this->aryOptions['uidfilter']);
    }

    /**
     * Were any errors encountered while attempting to authenticate
     * @return bool
     */
    public function wasErrorEncountered()
    {
        return (count($this->aryErrors) > 0) ? true : false;
    }

    /**
     * Display the errors that were encountered, if applicable
     * @return void
     */
    public function displayErrors()
    {
        if(count($this->aryErrors) > 0){
            echo '<h3>Errors Encountered</h3>',PHP_EOL,'<ul>',PHP_EOL;
            foreach ($this->aryErrors as $aryError){
                echo '<li>',PHP_EOL,'<h4>Error at line ',$aryError['line'],'</h4>',PHP_EOL,'<p>',$aryError['msg'],'</p>',PHP_EOL,'</li>',PHP_EOL;
            }
            echo '</ul>',PHP_EOL;
        } else {
            echo '<h2>No errors encountered</h2>',PHP_EOL;
        }
    }

    /**
     * @param $strMsg
     */
    public function displayStatus($strMsg)
    {
        echo '<p>',ucfirst($strMsg),'... success!</p>',PHP_EOL;
    }

    /**
     * Attempt to authenticate $strUser using $strFilter to find user DN
     *
     * Checks $strUser and $strPassword for empty, checks both against regex patterns, attempts to bind using
     * bind account, then looks up user DN using $strFilter, then attempts to bind using user DN and $strPassword
     *
     * @param string $strUser
     * @param string $strPassword
     * @param string $strFilter
     * @return bool
     */
    protected function auth($strUser,$strPassword,$strFilter)
    {
        /**
         * Let's check the user
         */
        if(empty($strUser)){
            $this->recordError('empty uid',__LINE__);
            return false;
        }

        if(preg_match($this->aryOptions['uidpattern'],$strUser)){
            $this->recordError('bad uid',__LINE__);
            return false;
        } else {
            $this->displayStatus('checking uid against regex pattern');
        }

        /**
         * Now check the password
         */
        if(empty($strPassword)){
            $this->recordError('empty password',__LINE__);
            return false;
        }

        if(preg_match($this->aryOptions['passwordpattern'],$strPassword) || strlen($strPassword) < $this->aryOptions['passwordmin'] || strlen($strPassword) > $this->aryOptions['passwordmax']){
            $this->recordError('bad password',__LINE__);
            return false;
        } else {
            $this->displayStatus('checking user password against regex pattern, min/max lengths');
        }

        if($this->aryOptions['useldaps']){
            $this->aryLDAPParams['ldapserver'] = 'ldaps://' . $this->aryLDAPParams['ldapserver'];
            if(isset($this->aryLDAPParams['ldapport']) && '' != $this->aryLDAPParams['ldapport']){
                $this->aryLDAPParams['ldapserver'] .= ':'. $this->aryLDAPParams['ldapport'];
            }
        }

        /*
         * As of PHP7, if you pass in something other than a valid port number for the port param, you're going to have
         * a bad time.  And if we're doing ldaps, then the port number is ignored
         */
        if($this->aryOptions['useldaps'] || !is_integer($this->aryLDAPParams['ldapport'])){
            $this->rscConnection = ldap_connect($this->aryLDAPParams['ldapserver']);
        } else {
            $this->rscConnection = ldap_connect($this->aryLDAPParams['ldapserver'],$this->aryLDAPParams['ldapport']);
        }

        /**
         * Now let's actually start
         */
        if(FALSE === $this->rscConnection){
            $this->recordError('connection failed',__LINE__);
            return false;
        } else {
            $this->displayStatus('setting up initial connection with '.$this->aryLDAPParams['ldapserver']);
        }
        echo '</p>',PHP_EOL;

        //if we want tls we HAVE to use v3
        if($this->aryOptions['useldap3'] || $this->aryOptions['starttls']){
            if(!ldap_set_option($this->rscConnection,LDAP_OPT_PROTOCOL_VERSION,3)){
                $this->recordError('v3 of ldap protocol not supported',__LINE__);
                return false;
            } else {
                /**
                 * Copes with W2K3/AD issue.
                 * @see http://bugs.php.net/bug.php?id=30670
                 * and
                 * @see http://php.net/manual/en/function.ldap-search.php#45388
                 *
                 */
                ldap_set_option($this->rscConnection,LDAP_OPT_REFERRALS,0);
                $this->displayStatus('requesting switch to v3 of ldap protocol');
                if($this->aryOptions['starttls']){
                    if(!ldap_start_tls($this->rscConnection)){

                        $this->recordError(sprintf($this->strStartTLSErrorMsg,$this->aryLDAPParams['ldapserver']),__LINE__);
                        return false;
                    } else {
                        $this->displayStatus('requesting start_tls');
                    }
                }
            }
        }

        /**
         * now lets attempt to bind
         */
        if(!ldap_bind($this->rscConnection,$this->aryLDAPParams['bindaccount'].'@'.$this->aryLDAPParams['addomain'],$this->aryLDAPParams['bindpass'])){
            $this->recordError('unable to bind with bind account ('. $this->aryLDAPParams['bindaccount'] .')',__LINE__);
            return false;
        } else {
            $this->displayStatus('attempting to bind with bind account ('. $this->aryLDAPParams['bindaccount'] .')');
        }

        $strSearch = $strFilter.$strUser;

        if(false === $rscSearchResult = ldap_search($this->rscConnection,$this->aryLDAPParams['basedn'],$strSearch)){
            $this->recordError(sprintf($this->strLDAPSearchErrMsg,$strUser,$strSearch,$this->aryLDAPParams['basedn']),__LINE__);
            return false;
        } else {
            $this->displayStatus('performing search for user using filter <strong>'.$strSearch.'</strong>');
        }

        if(false === $rscEntry = ldap_first_entry($this->rscConnection,$rscSearchResult)){
            $this->recordError('problem encountered retrieving search results',__LINE__);
            return false;
        } else {
            $this->displayStatus('attempting to retrieve record for search match');
        }

        if(empty($rscEntry)){
            $this->recordError('no matches for search',__LINE__);
            return false;
        }

        if(false === $strUserDN = ldap_get_dn($this->rscConnection,$rscEntry)){
            $this->recordError('problem encountered retrieving users DN',__LINE__);
            return false;
        } else {
            $this->displayStatus('attempting to retrieve user\'s DN from search match');
        }

        /**
         * ok, we finally have the user's DN, let's see if we can bind with it
         */

        $boolReturn = ldap_bind($this->rscConnection,$strUserDN,$strPassword);
        ldap_unbind($this->rscConnection);

        if($boolReturn){
            $this->displayStatus('attempting to bind with user\'s DN and password');
        }

        return $boolReturn;

    }

    /**
     * Records an error when encountered
     * @param string $strMessage
     * @param integer $intLine
     * @return void
     */
    private function recordError($strMessage,$intLine)
    {
        //because the actual problem occurs right after we record it
        $intLine = $intLine - 1;
        $strLDAPError = ldap_error($this->rscConnection);
        if(!empty($strLDAPError) && 'Success' !== $strLDAPError){
            $strMessage .= '. Last LDAP error: ' . $strLDAPError;
        }

        $this->aryErrors[] = array('line'=>$intLine,'msg'=>$strMessage);
    }
}