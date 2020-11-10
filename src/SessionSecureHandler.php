<?php

namespace Adirona\SessionSecureHandler;

use Adirona\EncryptionDecryptionService\EncryptionDecryptionService;
use SessionHandler;

class SessionSecureHandler extends SessionHandler
{

    protected $key, $name, $cookie, $encryptionDecryptionHandler;

    public function __construct(EncryptionDecryptionService $encryptionDecryptionHandler,
                                $key = null,
                                array $extendedSettings = [])
    {
        $this->key = $key === null ? bin2hex(random_bytes(16)) : $key;
        $this->name = 'MY_SESSION';
        $this->cookie = [];
        $this->encryptionDecryptionHandler = $encryptionDecryptionHandler;

        $this->cookie += [
            'lifetime' => 0,
            'path' => ini_get('session.cookie_path'),
            'domain' => ini_get('session.cookie_domain'),
            'secure' => isset($_SERVER['HTTPS']),
            'httponly' => true
        ];

        $this->setup($extendedSettings);
    }

    private function setup($extendedSettings)
    {
        ini_set('session.use_cookies', 1);
        ini_set('session.use_only_cookies', 1);

        foreach ($extendedSettings as $init => $value) {
            ini_set($init, $value);
        }

        session_name($this->name);

        session_set_cookie_params(
            $this->cookie['lifetime'],
            $this->cookie['path'],
            $this->cookie['domain'],
            $this->cookie['secure'],
            $this->cookie['httponly']
        );
    }

    public function setSessionName($sessionName)
    {
        $this->name = $sessionName;
    }

    public function start()
    {
        if ((session_id() === '') && session_start()) {
            return mt_rand(0, 4) === 0 ? $this->refresh() : true; // 1/5
        }

        return false;
    }

    public function forget()
    {
        if (session_id() === '') {
            return false;
        }

        $_SESSION = [];

        setcookie(
            $this->name,
            '',
            time() - 42000,
            $this->cookie['path'],
            $this->cookie['domain'],
            $this->cookie['secure'],
            $this->cookie['httponly']
        );

        return session_destroy();
    }

    public function refresh()
    {
        return session_regenerate_id(true);
    }

    public function read($id)
    {
        return $this->encryptionDecryptionHandler->decrypt(parent::read($id), $this->key);
    }

    public function write($id, $data)
    {
        return parent::write($id, $this->encryptionDecryptionHandler->encrypt($data, $this->key));
    }

    public function isExpired($ttl = 30)
    {
        $last = isset($_SESSION['_last_activity'])
            ? $_SESSION['_last_activity']
            : false;

        if ($last !== false && time() - $last > $ttl * 60) {
            return true;
        }

        $_SESSION['_last_activity'] = time();

        return false;
    }

    public function isFingerprint()
    {
        $hash = md5(
            $_SERVER['HTTP_USER_AGENT'] .
            (ip2long($_SERVER['REMOTE_ADDR']) & ip2long('255.255.0.0'))
        );

        if (isset($_SESSION['_fingerprint'])) {
            return $_SESSION['_fingerprint'] === $hash;
        }

        $_SESSION['_fingerprint'] = $hash;

        return true;
    }

    public function isValid()
    {
        return !$this->isExpired() && $this->isFingerprint();
    }

    public function get($name)
    {
        $parsed = explode('.', $name);

        $result = $_SESSION;

        while ($parsed) {
            $next = array_shift($parsed);

            if (isset($result[$next])) {
                $result = $result[$next];
            } else {
                return null;
            }
        }

        return $result;
    }

    public function put($name, $value)
    {
        $parsed = explode('.', $name);

        $session =& $_SESSION;

        while (count($parsed) > 1) {
            $next = array_shift($parsed);

            if (!isset($session[$next]) || !is_array($session[$next])) {
                $session[$next] = [];
            }

            $session =& $session[$next];
        }

        $session[array_shift($parsed)] = $value;
    }

    public function all()
    {
        return (array)$_SESSION;
    }

    public function remove($sessionKey)
    {
        unset($_SESSION[$sessionKey]);
    }

}