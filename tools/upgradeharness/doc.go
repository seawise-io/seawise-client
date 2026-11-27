// Package upgradeharness runs published 1.x client images and the agent
// image on the same data volume against a local stand-in for the SeaWise
// API, on a Docker network without internet access. The tests need Docker
// and the upgradeharness build tag; run.sh builds the images and runs them.
package upgradeharness
