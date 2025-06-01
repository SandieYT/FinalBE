export const setUploadPreset = (presetName) => (req, res, next) => {
  req.uploadPreset = presetName;
  next()
};
