// Kata-native GPU device plugin (reference implementation).
//
// Назначение: адвертайзить nvidia.com/gpu для vfio-GPU, пробрасываемых в Kata,
// НЕ инжектя контейнерные vfio-девайсы (в отличие от GPU-Operator sandbox-plugin,
// который отдаёт volume-mounts и ломает plain-Kata runtime-rs: "initialize vfio device ENOENT").
//
// Механизм: Allocate возвращает CDI-устройства (k8s deviceplugin v1beta1 CDIDevices).
// kubelet проставит аннотации cdi.k8s.io/*, containerd/runtime-rs их применит, а CDI-spec
// (kind nvidia.com/TU104GL_QUADRO_RTX_4000) Kata использует для cold-plug GPU в VM.
//
// Требует k8s >= 1.29 (deviceplugin v1beta1 CDIDevices) и CDI spec, доступный на узле
// (например /etc/cdi/nvidia-tu104.json с kind nvidia.com/TU104GL_QUADRO_RTX_4000 и devices
// по BDF). Собирать/публиковать как обычный образ (напр. kaniko, как в
// mlscan deploy/v3/images/nvidia-device-plugin/), запускать DaemonSet'ом с монтированием
// /var/lib/kubelet/device-plugins и /etc/cdi (ro).
//
// Подстройте под задачу: список BDF, kind, resourceName. Секретов не содержит.

package main

import (
	"context"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

const (
	resourceName   = "nvidia.com/gpu"
	cdiKind        = "nvidia.com/TU104GL_QUADRO_RTX_4000"
	devicePluginDir = "/var/lib/kubelet/device-plugins"
	socketName      = "nvidia-cdi.sock"
)

// BDF vfio-GPU, которые нужно адвертайзить (из /sys/bus/pci + vfio-manager).
var devices = []string{"0000:05:00.0", "0000:84:00.0"}

type server struct {
	pluginapi.UnimplementedDevicePluginServer
}

func (s *server) GetDevicePluginOptions(context.Context, *pluginapi.Empty) (*pluginapi.DevicePluginOptions, error) {
	return &pluginapi.DevicePluginOptions{}, nil
}

func (s *server) ListAndWatch(_ *pluginapi.Empty, stream pluginapi.DevicePlugin_ListAndWatchServer) error {
	var ds []*pluginapi.Device
	for _, id := range devices {
		ds = append(ds, &pluginapi.Device{ID: id, Health: pluginapi.Healthy})
	}
	if err := stream.Send(&pluginapi.ListAndWatchResponse{Devices: ds}); err != nil {
		return err
	}
	select {} // держим стрим открытым
}

func (s *server) Allocate(_ context.Context, req *pluginapi.AllocateRequest) (*pluginapi.AllocateResponse, error) {
	resp := &pluginapi.AllocateResponse{}
	for _, cr := range req.ContainerRequests {
		out := &pluginapi.ContainerAllocateResponse{}
		for _, id := range cr.DevicesIDs {
			out.CDIDevices = append(out.CDIDevices, &pluginapi.CDIDevice{Name: cdiKind + "=" + id})
		}
		resp.ContainerResponses = append(resp.ContainerResponses, out)
	}
	return resp, nil
}

func (s *server) GetPreferredAllocation(context.Context, *pluginapi.PreferredAllocationRequest) (*pluginapi.PreferredAllocationResponse, error) {
	return &pluginapi.PreferredAllocationResponse{}, nil
}

func (s *server) PreStartContainer(context.Context, *pluginapi.PreStartContainerRequest) (*pluginapi.PreStartContainerResponse, error) {
	return &pluginapi.PreStartContainerResponse{}, nil
}

func main() {
	sock := filepath.Join(devicePluginDir, socketName)
	_ = os.Remove(sock)
	lis, err := net.Listen("unix", sock)
	if err != nil {
		log.Fatalf("listen %s: %v", sock, err)
	}
	g := grpc.NewServer()
	pluginapi.RegisterDevicePluginServer(g, &server{})
	go func() { log.Fatal(g.Serve(lis)) }()

	conn, err := grpc.NewClient("unix://"+filepath.Join(devicePluginDir, "kubelet.sock"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial kubelet.sock: %v", err)
	}
	defer conn.Close()
	client := pluginapi.NewRegistrationClient(conn)
	req := &pluginapi.RegisterRequest{Version: pluginapi.Version, Endpoint: socketName, ResourceName: resourceName}
	for i := 0; i < 30; i++ {
		if _, err = client.Register(context.Background(), req); err == nil {
			break
		}
		log.Printf("register retry: %v", err)
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		log.Fatalf("register: %v", err)
	}
	log.Printf("registered %s endpoint=%s devices=%v", resourceName, socketName, devices)
	select {}
}
