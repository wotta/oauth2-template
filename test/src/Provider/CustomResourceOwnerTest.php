<?php

namespace League\OAuth2\Client\Test\Provider;

use PHPUnit\Framework\TestCase;
use Wotta\OAuth2\Client\Provider\CustomResourceOwner;

class CustomResourceOwnerTest extends TestCase
{
    public function testUrlIsNullWithoutDomainOrNickname(): void
    {
        $user = new CustomResourceOwner();

        $this->assertNull($user->getId());
    }

    public function testUrlIsNicknameWithoutDomain(): void
    {
        $uniqueId = uniqid();
        $user = new CustomResourceOwner(['id' => $uniqueId]);

        $id = $user->getId();

        $this->assertEquals($uniqueId, $id);
    }
}