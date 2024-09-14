<?php

namespace netcup\DNS\API;

final class Payload
{
    /**
     * @var string
     */
    private $user;

    /**
     * @var string
     */
    private $password;

    /**
     * @var string
     */
    private $hostname;

    /**
     * @var string
     */
    private $mode = "both";

    /**
     * @var string
     */
    private $ip;
    private $myip;

    /**
     * @var string
     */
    private $ip6;

    /**
     * @var bool
     */
    private $force = false;

    public function __construct(array $payload)
    {
        foreach (get_object_vars($this) as $key => $val) {
            if (isset($payload[$key])) {
                $this->$key = $payload[$key];
            }
	}
	if (!empty($this->myip)) {
	    $ips = explode(',', $this->myip);
	    $this->ip6 = $ips[0];
	    $this->ip = $ips[1];
	}
    }

    /**
     * @return bool
     */
    public function isValid()
    {
        return
            # !empty($this->user) &&
            # !empty($this->password) &&
            !empty($this->hostname) &&
            (
                (
                    !empty($this->ip) && $this->isValidIpv4()
                )
                ||
                (
                    !empty($this->ip6) && $this->isValidIpv6()
                )
            );
    }

    /**
     * @return string
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * @return string
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * @return string
     */
    public function getDomain()
    {
        return $this->hostname;
    }

    /**
     * @return array
     */
    public function getMatcher()
    {
        switch ($this->mode) {
            case 'both':
                return ['@', '*'];

            case '*':
                return ['*'];

            default:
                return ['@'];
        }
    }

    /**
     * there is no good way to get the correct "registrable" Domain without external libs!
     *
     * @see https://github.com/jeremykendall/php-domain-parser
     *
     * this method is still tricky, because:
     *
     * works: nas.tld.com
     * works: nas.tld.de
     * works: tld.com
     * failed: nas.tld.co.uk
     * failed: nas.home.tld.de
     *
     * @return string
     */
    public function getHostname()
    {
        // hack if top level domain are used for dynDNS
        if (1 === substr_count($this->hostname, '.')) {
            return $this->domain;
        }

        $domainParts = explode('.', $this->hostname);
        array_shift($domainParts); // remove sub domain
        return implode('.', $domainParts);
    }

    /**
     * @return string
     */
    public function getIpv4()
    {
        return $this->ip;
    }

    /**
     * @return bool
     */
    public function isValidIpv4()
    {
        return (bool)filter_var($this->ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    }

    /**
     * @return string
     */
    public function getIpv6()
    {
        return $this->ip6;
    }

    /**
     * @return bool
     */
    public function isValidIpv6()
    {
        return (bool)filter_var($this->ip6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    }

    /**
     * @return bool
     */
    public function isForce()
    {
        return $this->force;
    }
}
