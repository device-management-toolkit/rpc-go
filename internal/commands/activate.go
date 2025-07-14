/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

// This file serves as documentation that the activate command is now implemented
// in the internal/commands/activate package following the modular structure:
//
// internal/commands/activate/
// ├── activate.go      # Main ActivateCmd struct
// ├── local.go         # Local activation subcommand
// ├── remote.go        # Remote activation subcommand
// └── *_test.go        # Tests for each component
//
// The ActivateCmd is imported directly in cli.go from the activate package.
