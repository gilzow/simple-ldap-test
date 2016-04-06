<?php

$aryRequired = array(
    //account to use for binding
    'bindaccount'   => 'yourbindaccount',
    //bind account password
    'bindpass'      => 'yourbindaccountpassword',
    // ldap server address
    'ldapserver'   => 'yourtestaccount',
    //ldap port
    'ldapport'      => 3268,
    //LDAP domain
    'addomain'      => 'domain.com',
    //base dn for searching
    'basedn'        => 'dc=edu',
);

/**
 * Items you can change.  The defaults are shown.  To use, create an array with these keys and pass in as the second
 * parameter upon construction of the LDAP_Test object

$aryOptions = array(
    //should be we use LDAP v3?
    'useldap3'          => true,
    // use TLS?
    'starttls'          => true,
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
        'uidpattern'        => '/[^A-z0-9@.-]+/',
        'passwordpattern'   => '/[^A-z0-9(*&)=?|^}\/_>#:-[\052];]~,\[<.]+/',
        'passwordmin'       => 8,
        'passwordmax'       => 26,
    );

    protected $aryOptions = array();
    
    private $aryErrors = array();

    protected $rscConnection = null;

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
        
    }

    /**
     * @param string $strEmailAddress
     * @param string $strPassword
     * @return bool
     */
    public function authEmail($strEmailAddress,$strPassword)
    {
        return $this->auth($strEmailAddress,$strPassword,'proxyAddresses=smtp:');
    }

    /**
     * @param string $strUser
     * @param string $strPassword
     * @return bool
     */
    public function authSSO($strUser,$strPassword)
    {
        return $this->auth($strUser,$strPassword,'sAMAccountName=');
    }

    /**
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
        }

        /**
         * Now let's actually start
         */
        if(FALSE === $this->rscConnection = ldap_connect($this->aryLDAPParams['ldapserver'],$this->aryLDAPParams['ldapport'])){
            $this->recordError('connection failed',__LINE__);
            return false;
        }

        //if we want tls we HAVE to use v3
        if($this->aryOptions['useldap3'] || $this->aryOptions['starttls']){
            if(!ldap_set_option($this->rscConnection,LDAP_OPT_PROTOCOL_VERSION,3)){
                $this->recordError('v3 of ldap protocol not supported',__LINE__);
                return false;
            } elseif($this->aryOptions['starttls']){
                if(!ldap_start_tls($this->rscConnection)){
                    $this->recordError('start tls failed to start',__LINE__);
                    return false;
                }
            }
        }

        /**
         * now lets attempt to bind
         */
        if(!ldap_bind($this->rscConnection,$this->aryLDAPParams['bindaccount'].'@'.$this->aryLDAPParams['addomain'],$this->aryLDAPParams['bindpassword'])){
            $this->recordError('unable to bind with bind account',__LINE__);
            return false;
        }

        $strSearch = $strFilter.$strUser;

        if(false === $rscSearchResult = ldap_search($this->rscConnection,$this->aryLDAPParams['basedn'],$strSearch)){
            $this->recordError('problem encoutered searching for user',__LINE__);
            return false;
        }

        if(false === $rscEntry = ldap_first_entry($this->rscConnection,$rscSearchResult)){
            $this->recordError('problem encountered retrieving search results',__LINE__);
            return false;
        }

        if(empty($rscEntry)){
            $this->recordError('no matches for search',__LINE__);
            return false;
        }

        if(false === $strUserDN = ldap_get_dn($this->rscConnection,$rscEntry)){
            $this->recordError('problem encountered retrieving users DN',__LINE__);
            return false;
        }

        /**
         * ok, we finally have the user's DN, let's see if we can bind with it
         */

        $boolReturn = ldap_bind($this->rscConnection,$strUserDN,$strPassword);
        ldap_unbind($this->rscConnection);

        if(false === $boolReturn){
            $this->recordError('unable to auth user with credentials given',__LINE__);
        }

        return $boolReturn;

    }

    /**
     * @param string $strMessage
     * @param integer $intLine
     */
    private function recordError($strMessage,$intLine)
    {
        //because the actual problem occurs right after we record it
        $intLine = $intLine - 1;
        $this->aryErrors[] = array('line'=>$intLine,'msg'=>$strMessage);
    }
}

$objMyLdap = new LDAP_Test($aryRequired);
