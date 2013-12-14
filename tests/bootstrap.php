<?php

use Doctrine\Common\Annotations\AnnotationRegistry;
use Composer\Autoload\ClassLoader;

$loader = require __DIR__ . '/../vendor/autoload.php';

// Add test namespaces
$loader->add('CrEOF\Security', __DIR__);

// Add fixture namespaces
$loader->add('Fixture', __DIR__ . '/CrEOF/Security');
$loader->add('OwnedEntity\Fixture', __DIR__ . '/CrEOF/Security');
$loader->add('Mapping\Fixture', __DIR__ . '/CrEOF/Security');

// Register loader with annotation registry
AnnotationRegistry::registerLoader([$loader, 'loadClass']);

// Register extension annotations annotation registry
CrEOF\Security\SecurityExtensions::registerAnnotations();
