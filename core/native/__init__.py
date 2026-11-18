"""Native core artifacts shipped inside a wheel.

A checkout builds its cores into ``transport/`` and ``rust-core/`` and the
bridges look there first. A wheel has no such tree, so
``tools/bundle_cores.py`` copies the artifacts built on the wheel's platform
into this package and the bridges fall back to it. Nothing here is imported;
this module only makes the directory a package so setuptools can carry its data
in the wheel.
"""
