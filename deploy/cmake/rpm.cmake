SET(CPACK_GENERATOR                         "RPM")
set(CPACK_SYSTEM_NAME                       "x86_64")
set(CPACK_RPM_PACKAGE_ARCHITECTURE          "x86_64")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE      "${CMAKE_CURRENT_SOURCE_DIR}/deploy/cmake/rpm_install.sh")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE     "${CMAKE_CURRENT_SOURCE_DIR}/deploy/cmake/rpm_uninstall.sh")
set(CPACK_RPM_SPEC_INSTALL_POST             "/bin/true") # disable strip
set(CPACK_RPM_PACKAGE_AUTOREQ               0)

