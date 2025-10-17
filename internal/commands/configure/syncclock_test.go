/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"errors"
	"testing"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/timesynchronization"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestSyncClockCmd_Validate(t *testing.T) {
	tests := []struct {
		name        string
		cmd         SyncClockCmd
		wantErr     bool
		description string
	}{
		{
			name: "password provided",
			cmd: SyncClockCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
					},
				},
			},
			wantErr:     false,
			description: "should succeed when password is provided",
		},
		// Missing password case removed: Validate no longer prompts; password ensured at Run.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()

			if tt.wantErr {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
			}
		})
	}
}

func TestSyncClockCmd_Run(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockWSMAN := mock.NewMockWSMANer(ctrl)

	t.Run("successful_clock_synchronization", func(t *testing.T) {
		cmd := &SyncClockCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					WSMan:       mockWSMAN,
				},
			},
		}

		ctx := &commands.Context{
			AMTCommand:  mockAMT,
			AMTPassword: "test-pass",
		}

		// Mock GetLowAccuracyTimeSynch
		ta0 := time.Now().Unix()
		lowAccuracyResponse := timesynchronization.Response{
			Body: timesynchronization.Body{
				GetLowAccuracyTimeSynchResponse: timesynchronization.GetLowAccuracyTimeSynchResponse{
					Ta0:         ta0,
					ReturnValue: 0,
				},
			},
		}
		mockWSMAN.EXPECT().GetLowAccuracyTimeSynch().Return(lowAccuracyResponse, nil)

		// Mock SetHighAccuracyTimeSynch
		highAccuracyResponse := timesynchronization.Response{
			Body: timesynchronization.Body{
				SetHighAccuracyTimeSynchResponse: timesynchronization.SetHighAccuracyTimeSynchResponse{
					ReturnValue: 0,
				},
			},
		}
		mockWSMAN.EXPECT().SetHighAccuracyTimeSynch(ta0, gomock.Any(), gomock.Any()).Return(highAccuracyResponse, nil)

		err := cmd.Run(ctx)
		assert.NoError(t, err)
	})

	t.Run("device_not_activated", func(t *testing.T) {
		cmd := &SyncClockCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 0,
					WSMan:       mockWSMAN,
				},
			},
		}

		ctx := &commands.Context{
			AMTCommand:  mockAMT,
			AMTPassword: "test-pass",
		}

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device is not activated")
	})

	t.Run("get_low_accuracy_time_synch_error", func(t *testing.T) {
		cmd := &SyncClockCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					WSMan:       mockWSMAN,
				},
			},
		}

		ctx := &commands.Context{
			AMTCommand:  mockAMT,
			AMTPassword: "test-pass",
		}

		// Mock GetLowAccuracyTimeSynch to return an error
		mockWSMAN.EXPECT().GetLowAccuracyTimeSynch().Return(timesynchronization.Response{}, errors.New("low accuracy time error"))

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get low accuracy time")
	})

	t.Run("get_low_accuracy_time_synch_pt_code_error", func(t *testing.T) {
		cmd := &SyncClockCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					WSMan:       mockWSMAN,
				},
			},
		}

		ctx := &commands.Context{
			AMTCommand:  mockAMT,
			AMTPassword: "test-pass",
		}

		// Mock GetLowAccuracyTimeSynch with non-zero return value
		lowAccuracyResponse := timesynchronization.Response{
			Body: timesynchronization.Body{
				GetLowAccuracyTimeSynchResponse: timesynchronization.GetLowAccuracyTimeSynchResponse{
					Ta0:         time.Now().Unix(),
					ReturnValue: 1, // Non-zero indicates failure
				},
			},
		}
		mockWSMAN.EXPECT().GetLowAccuracyTimeSynch().Return(lowAccuracyResponse, nil)

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get low accuracy time")
		assert.Contains(t, err.Error(), "AmtPtStatusCodeBase")
	})

	t.Run("set_high_accuracy_time_synch_error", func(t *testing.T) {
		cmd := &SyncClockCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					WSMan:       mockWSMAN,
				},
			},
		}

		ctx := &commands.Context{
			AMTCommand:  mockAMT,
			AMTPassword: "test-pass",
		}

		// Mock GetLowAccuracyTimeSynch successfully
		ta0 := time.Now().Unix()
		lowAccuracyResponse := timesynchronization.Response{
			Body: timesynchronization.Body{
				GetLowAccuracyTimeSynchResponse: timesynchronization.GetLowAccuracyTimeSynchResponse{
					Ta0:         ta0,
					ReturnValue: 0,
				},
			},
		}
		mockWSMAN.EXPECT().GetLowAccuracyTimeSynch().Return(lowAccuracyResponse, nil)

		// Mock SetHighAccuracyTimeSynch to return an error
		mockWSMAN.EXPECT().SetHighAccuracyTimeSynch(ta0, gomock.Any(), gomock.Any()).Return(timesynchronization.Response{}, errors.New("high accuracy time error"))

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set high accuracy time")
	})

	t.Run("set_high_accuracy_time_synch_pt_code_error", func(t *testing.T) {
		cmd := &SyncClockCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					WSMan:       mockWSMAN,
				},
			},
		}

		ctx := &commands.Context{
			AMTCommand:  mockAMT,
			AMTPassword: "test-pass",
		}

		// Mock GetLowAccuracyTimeSynch successfully
		ta0 := time.Now().Unix()
		lowAccuracyResponse := timesynchronization.Response{
			Body: timesynchronization.Body{
				GetLowAccuracyTimeSynchResponse: timesynchronization.GetLowAccuracyTimeSynchResponse{
					Ta0:         ta0,
					ReturnValue: 0,
				},
			},
		}
		mockWSMAN.EXPECT().GetLowAccuracyTimeSynch().Return(lowAccuracyResponse, nil)

		// Mock SetHighAccuracyTimeSynch with non-zero return value
		highAccuracyResponse := timesynchronization.Response{
			Body: timesynchronization.Body{
				SetHighAccuracyTimeSynchResponse: timesynchronization.SetHighAccuracyTimeSynchResponse{
					ReturnValue: 1, // Non-zero indicates failure
				},
			},
		}
		mockWSMAN.EXPECT().SetHighAccuracyTimeSynch(ta0, gomock.Any(), gomock.Any()).Return(highAccuracyResponse, nil)

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set high accuracy time")
		assert.Contains(t, err.Error(), "AmtPtStatusCodeBase")
	})

	t.Run("ccm_mode_activation", func(t *testing.T) {
		cmd := &SyncClockCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					WSMan:       mockWSMAN,
				},
			},
		}

		ctx := &commands.Context{
			AMTCommand:  mockAMT,
			AMTPassword: "test-pass",
		}

		// Mock GetLowAccuracyTimeSynch
		ta0 := time.Now().Unix()
		lowAccuracyResponse := timesynchronization.Response{
			Body: timesynchronization.Body{
				GetLowAccuracyTimeSynchResponse: timesynchronization.GetLowAccuracyTimeSynchResponse{
					Ta0:         ta0,
					ReturnValue: 0,
				},
			},
		}
		mockWSMAN.EXPECT().GetLowAccuracyTimeSynch().Return(lowAccuracyResponse, nil)

		// Mock SetHighAccuracyTimeSynch
		highAccuracyResponse := timesynchronization.Response{
			Body: timesynchronization.Body{
				SetHighAccuracyTimeSynchResponse: timesynchronization.SetHighAccuracyTimeSynchResponse{
					ReturnValue: 0,
				},
			},
		}
		mockWSMAN.EXPECT().SetHighAccuracyTimeSynch(ta0, gomock.Any(), gomock.Any()).Return(highAccuracyResponse, nil)

		err := cmd.Run(ctx)
		assert.NoError(t, err)
	})

	t.Run("acm_mode_activation", func(t *testing.T) {
		cmd := &SyncClockCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 2,
					WSMan:       mockWSMAN,
				},
			},
		}

		ctx := &commands.Context{
			AMTCommand:  mockAMT,
			AMTPassword: "test-pass",
		}

		// Mock GetLowAccuracyTimeSynch
		ta0 := time.Now().Unix()
		lowAccuracyResponse := timesynchronization.Response{
			Body: timesynchronization.Body{
				GetLowAccuracyTimeSynchResponse: timesynchronization.GetLowAccuracyTimeSynchResponse{
					Ta0:         ta0,
					ReturnValue: 0,
				},
			},
		}
		mockWSMAN.EXPECT().GetLowAccuracyTimeSynch().Return(lowAccuracyResponse, nil)

		// Mock SetHighAccuracyTimeSynch
		highAccuracyResponse := timesynchronization.Response{
			Body: timesynchronization.Body{
				SetHighAccuracyTimeSynchResponse: timesynchronization.SetHighAccuracyTimeSynchResponse{
					ReturnValue: 0,
				},
			},
		}
		mockWSMAN.EXPECT().SetHighAccuracyTimeSynch(ta0, gomock.Any(), gomock.Any()).Return(highAccuracyResponse, nil)

		err := cmd.Run(ctx)
		assert.NoError(t, err)
	})

	t.Run("zero_ta0_value", func(t *testing.T) {
		cmd := &SyncClockCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					WSMan:       mockWSMAN,
				},
			},
		}

		ctx := &commands.Context{
			AMTCommand:  mockAMT,
			AMTPassword: "test-pass",
		}

		// Mock GetLowAccuracyTimeSynch with Ta0 = 0
		lowAccuracyResponse := timesynchronization.Response{
			Body: timesynchronization.Body{
				GetLowAccuracyTimeSynchResponse: timesynchronization.GetLowAccuracyTimeSynchResponse{
					Ta0:         0, // Zero value
					ReturnValue: 0,
				},
			},
		}
		mockWSMAN.EXPECT().GetLowAccuracyTimeSynch().Return(lowAccuracyResponse, nil)

		// Mock SetHighAccuracyTimeSynch with Ta0 = 0
		highAccuracyResponse := timesynchronization.Response{
			Body: timesynchronization.Body{
				SetHighAccuracyTimeSynchResponse: timesynchronization.SetHighAccuracyTimeSynchResponse{
					ReturnValue: 0,
				},
			},
		}
		mockWSMAN.EXPECT().SetHighAccuracyTimeSynch(int64(0), gomock.Any(), gomock.Any()).Return(highAccuracyResponse, nil)

		err := cmd.Run(ctx)
		assert.NoError(t, err)
	})
}
