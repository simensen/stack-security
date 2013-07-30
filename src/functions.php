<?php

namespace Stack\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

function authenticate(
    HttpKernelInterface $app,
    $challenge,
    array $firewalls,
    Request $request,
    $type = HttpKernelInterface::MASTER_REQUEST,
    $catch = true
) {
    $delegate = function ($checkAuthorization = true) use ($app, $challenge, $request, $type, $catch) {
        return \Stack\Security\delegate_authorization($app, $challenge, $request, $type, $catch, $checkAuthorization);
    };

    if ($request->attributes->has('stack.authn.token')) {
        // If the request already has a Stack authentication token
        // we should delegate but leave open the possiblity that
        // we might challenge.
        //
        // TODO: Should this be optional or otherwise configurable?
        return [true, call_user_func($delegate), null];
    }

    if (null === $firewall = match_firewall($request, $firewalls)) {
        // If no firewalls are matched we should delegate and set
        // $checkAuthorization to false to ensure that we do not
        // try to challenge if authorization fails.
        return [true, call_user_func($delegate, false), $firewall];
    }

    if ($request->headers->has('authorization')) {
        // If we have an authorization header we should pass back our
        // delegate and let the middleware requesting authentication
        // to handle it.
        return [false, $delegate, $firewall];
    }

    if ($firewall['anonymous']) {
        // We should delegate for anonymous requests but since
        // we found a firewall for this request we should
        // challenge if authorization fails.
        return [true, call_user_func($delegate), $firewall];
    }

    // Since we do not allow anonymous requests and we found
    // a firewall for this request we should challenge
    // immediately.
    $response = (new Response)->setStatusCode(401);

    return [true, call_user_func($challenge, $response), $firewall];
}


function delegate_authorization(
    HttpKernelInterface $app,
    $challenge,
    Request $request,
    $type = HttpKernelInterface::MASTER_REQUEST,
    $catch = true,
    $checkAuthorization = true
) {
    $response = $app->handle($request, $type, $catch);

    if (!$checkAuthorization) {
        return $response;
    }

    if ($response->getStatusCode()==401 && $response->headers->get('WWW-Authenticate') === 'Stack') {
        // By convention, we look for 401 response that has a WWW-Authenticate with field value of
        // Stack. In that case, we should pass the response to the delegatee's challenge callback.
        $response = call_user_func($challenge, $response);
    }

    return $response;
}

function delegate_missing_authentication(array $firewall, $delegate, $challenge)
{
    if ($firewall['anonymous']) {
        // If anonymous requests are allowed by our firewall we should
        // hand off to the delegate.
        return call_user_func($delegate);
    }

    // Otherwise, we should challenge immediately.
    // We use $challenge to be slightly more DRY.
    $response = (new Response)->setStatusCode(401);
    call_user_func($challenge, $response);

    return $response;
}

function match_firewall(Request $request, array $firewalls)
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
