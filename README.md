# block-device-snapshot

This specification is related to a Linux Kernel Module (LKM) implementing a snapshot service for block devices hosting file systems. The setup/switch-off of the service needs to be carried out via the following two API functions:

    activate_snapshot(char * dev_name, char * passwd)
    deactivate_snapshot(char * dev_name, char * passwd) 

When activating the snapshot, the dev_name needs to be recorded at kernel level, so that when the device associated with that name gets mounted then the snapshot service for the corresponding file system gets activated. At the same time, the snapshot deactivating API is used to notify that such snapshot service does not need to occur any-longer for that specific dev_name upon remounting it. The passwd parameter needs to be a credential managed by the snapshot service (not corresponding to any credential used for logging into the system) so that the thread which calls one of the above two API functions can be authenticated. In order for the above API not to fail, the calling thread also needs to have (effective-)root-id.

For "loop" devices, the dev_name parameter will correspond to the actual path-name associated to the file managed as device-file.

When the snapshot service gets activated, a subdirectory needs to be created in the /snapshot directory of the root file system. Such subdirectory should keep any file and data that represent the snapshot being managed. The subdirectory should have a name expressing the original dev_name for which the snapshot has been activated and a timestamp indicating the time of the mount operation of that device.

When the snapshot service is active for a device, we need to be able to log the original content of any block that is modified by VFS operations occurring on the file system hosted on the device. Restoring the content of these modified blocks allows therefore to rebuild the exact content of that file system prior its mount operation.

Deferred work is expected to be exploited for keeping low the on-critical-path activity executed by the snapshot service along the application threads using VFS.

The overall project will also need to offer a facility for restoring the snapshot of the device after the corresponding file system has been un-mounted. This part of the project can be limited to device-file management.

The project needs to be testable using the minimal file system layout and logic available via the following link.
