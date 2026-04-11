let incidents = [];

function addIncident(incident) {
  incidents.push(incident);
}

function getIncidents() {
  return incidents;
}

module.exports = { addIncident, getIncidents };