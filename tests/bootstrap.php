<?php

use Doctrine\Common\Annotations\AnnotationRegistry;
use Doctrine\Common\Annotations\AnnotationReader;
use Doctrine\Common\Annotations\CachedReader;
use Doctrine\Common\Cache\ArrayCache;
use Composer\Autoload\ClassLoader;


define('TESTS_PATH', __DIR__);
define('TESTS_TEMP_DIR', __DIR__ . '/temp');
define('VENDOR_PATH', realpath(__DIR__ . '/../vendor'));

$loader = require __DIR__ . '/../vendor/autoload.php';

$loader->add('Tool', __DIR__ . '/CrEOF/Security');

// Fixture namespaces
$loader->add('Fixture', __DIR__ . '/CrEOF/Security');
$loader->add('OwnedEntity\\Fixture', __DIR__ . '/CrEOF/Security');
$loader->add('Mapping\\Fixture', __DIR__ . '/CrEOF/Security');

AnnotationRegistry::registerLoader([$loader, 'loadClass']);

CrEOF\Security\SecurityExtensions::registerAnnotations();

$reader = new AnnotationReader();
$reader = new CachedReader($reader, new ArrayCache());

$_ENV['annotation_reader'] = $reader;
