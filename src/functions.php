<?php

namespace Stack\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

function delegate_authorization(
    HttpKernelInterface $app,
    $challenge,
    Request $request,
    $type = HttpKernelInterface::MASTER_REQUEST,
    $catch = true
) {
    $response = $app->handle($request, $type, $catch);

    if ($response->getStatusCode()==401 && $request->headers->get('WWW-Authenticate') === 'Stack') {
        // By convention, we look for 401 response that has a WWW-Authenticate with field value of
        // Stack. In that case, we should pass the response to the delegatee's challenge callback.
        $response = call_user_func($challenge, $response);
    }

    return $response;
}

function resolve_firewall(Request $request, array $firewalls = [])
{
    if (!$firewalls) {
        // By default we should firewall the root request and not allow
        // anonymous requests. (will force challenge immediately)
        $firewalls = [
            ['path' => '/']
        ];
    }

    $sortedFirewalls = array();
    foreach ($firewalls as $firewall) {
        if (!isset($firewall['anonymous'])) {
            $firewall['anonymous'] = false;
        }

        if (isset($sortedFirewalls[$firewall['path']])) {
            throw new \InvalidArgumentException("Path '".$firewall['path']."' specified more than one time.");
        }

        $sortedFirewalls[$firewall['path']] = $firewall;
    }

    ksort($sortedFirewalls);

    foreach ($sortedFirewalls as $path => $firewall) {
        if (0 === strpos($request->getRequestUri(), $path)) {
            return $firewall;
        }
    }

    return null;
}
