AC_DEFUN([PDNS_CHECK_GEOIP], [
  PKG_CHECK_MODULES([GEOIP], [geoip])
  PKG_CHECK_MODULES([YAML], [yaml-cpp >= 0.5])
])