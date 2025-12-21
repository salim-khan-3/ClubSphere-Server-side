require("dotenv").config();
const Stripe = require("stripe");
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const serviceAccount = require("./serviceKey.json");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY); // store secret in env

// ClubSphereDBUser
// 6j9L7FTbxlTfzF5m
const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.qr2egdp.mongodb.net/?appName=Cluster0`;

app.get("/", (req, res) => {
  res.send("simple crud server is running....");
});

// ===============================
// Token verification middleware
// ===============================
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  const idToken = authHeader.split("Bearer ")[1].trim();

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken; // এখানে uid, email ইত্যাদি পাবে
    next();
  } catch (error) {
    console.error("Token verification failed:", error.message);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    const db = client.db("ClubSphereDBUser");
    const userCollection = db.collection("users");
    const clubCollection = db.collection("clubs");
    const membershipCollection = db.collection("memberships");
    const eventCollection = db.collection("events");
    const eventRegistrationCollection = db.collection("eventRegistrations");
    const paymentCollection = db.collection("payments");

    // =====================
    // Role-check middleware
    // =====================
    const verifyAdmin = async (req, res, next) => {
      try {
        const email = req.user?.email;
        if (!email)
          return res.status(401).json({ message: "No email in token" });

        const user = await userCollection.findOne({ email });
        if (!user || user.role !== "admin") {
          return res
            .status(403)
            .json({ message: "Forbidden: Admin access required" });
        }
        next();
      } catch (err) {
        res.status(500).json({ message: "Server error" });
      }
    };

    // ==========================
    // user collection api
    // ==========================
    app.post("/users", async (req, res) => {
      const user = req.body;
      try {
        const existingUser = await userCollection.findOne({
          email: user.email,
        });

        if (!existingUser) {
          const newUser = {
            ...user,
            role: "member",
            createdAt: new Date(),
          };

          const result = await userCollection.insertOne(newUser);
          return res.send(result);
        }

        res.send({ message: "User already exists", user: existingUser });
      } catch (err) {
        res.status(500).send({ error: err.message });
      }
    });
    app.get("/users/:email", async (req, res) => {
      const email = req.params.email;
      const user = await userCollection.findOne({ email });
      if (!user) return res.status(404).json({ message: "User not found" });
      res.json(user);
    });
    app.patch("/users/:email", async (req, res) => {
      try {
        const email = req.params.email;
        const { name, photoURL } = req.body;

        if (!name && !photoURL) {
          return res.status(400).json({ message: "No data to update" });
        }

        const result = await userCollection.updateOne(
          { email },
          { $set: { name, photoURL, updatedAt: new Date() } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        const updatedUser = await userCollection.findOne({ email });
        res.json(updatedUser);
      } catch (error) {
        console.error("Update user error:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    // All users fetch (Admin only)
    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const users = await userCollection.find().toArray();
        res.send(users);
      } catch (err) {
        res.status(500).send({ message: "Error fetching users" });
      }
    });

    // Change user role (Admin only)
    app.patch(
      "/users/role/:email",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const email = req.params.email.toLowerCase();
        const { role } = req.body;
        const allowedRoles = ["admin", "clubManager", "member"];

        if (!allowedRoles.includes(role)) {
          return res.status(400).send({ message: "Invalid role" });
        }

        // Prevent admin from demoting themselves
        if (req.user?.email === email && role !== "admin") {
          return res
            .status(403)
            .send({ message: "Admin cannot change their own role" });
        }

        try {
          const result = await userCollection.updateOne(
            { email },
            { $set: { role, updatedAt: new Date() } }
          );

          if (result.matchedCount === 0) {
            return res.status(404).send({ message: "User not found" });
          }

          if (result.modifiedCount === 0) {
            return res.send({ message: "Role already assigned" });
          }
          res.send({ success: true, message: `Role updated to ${role}` });
        } catch (err) {
          console.error("Error updating role:", err);
          res
            .status(500)
            .send({ message: "Error updating role", error: err.message });
        }
      }
    );

    // ==========================
    // club collection api
    // ==========================

    app.post("/clubs", async (req, res) => {
      try {
        const clubData = req.body;
        if (
          !clubData.clubName ||
          !clubData.description ||
          !clubData.managerEmail
        )
          return res.status(400).send({ message: "Missing required fields" });

        // Check if club with same name exists
        const existingClub = await clubCollection.findOne({
          clubName: clubData.clubName,
        });
        if (existingClub) {
          return res
            .status(400)
            .send({ message: "Club with this name already exists" });
        }

        const newClub = {
          ...clubData,
          membershipFee: Number(clubData.membershipFee) || 0,
          status: "pending",
          members: [],
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const result = await clubCollection.insertOne(newClub);
        res.status(201).send({
          message: "Club created successfully",
          clubId: result.insertedId,
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Server error" });
      }
    });

    app.get("/clubs/my-clubs", async (req, res) => {
      try {
        const managerEmail = req.query.email;

        if (!managerEmail) {
          return res.status(400).send({ message: "Manager email is required" });
        }

        const myClubs = await clubCollection
          .find({ managerEmail: managerEmail })
          .toArray();

        console.log("Fetched clubs:", myClubs);

        res.send(myClubs);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Error fetching manager clubs" });
      }
    });

    app.get("/clubs/all", async (req, res) => {
      try {
        const clubs = await clubCollection.find().toArray();
        console.log("Fetched clubs:", clubs);
        res.send(clubs);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Error fetching all clubs" });
      }
    });

    app.get("/clubs/:id", async (req, res) => {
      const { id } = req.params;

      // ID validation
      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid ID format" });
      }

      try {
        const club = await clubCollection.findOne({ _id: new ObjectId(id) });

        if (!club) {
          return res.status(404).json({ message: "Club not found" });
        }

        res.json(club);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });
    app.patch("/clubs/approve/:id", async (req, res) => {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid ID format" });
      }

      try {
        const result = await clubCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: "approved", updatedAt: new Date() } }
        );

        res.send({ message: "Club approved", result });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Error approving club" });
      }
    });

    app.patch("/clubs/reject/:id", async (req, res) => {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid ID format" });
      }

      try {
        const result = await clubCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: "rejected", updatedAt: new Date() } }
        );

        res.send({ message: "Club rejected", result });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Error rejecting club" });
      }
    });
    app.patch("/clubs/:id", async (req, res) => {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid ID format" });
      }

      try {
        const updatedData = {
          ...req.body,
          updatedAt: new Date(),
        };

        const result = await clubCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        res.send({ success: true, result });
      } catch (err) {
        res.status(500).send({ message: "Failed to update club" });
      }
    });



    const verifyClubManager = async (req, res, next) => {
      try {
        const email = req.user?.email;
        if (!email) {
          return res.status(401).send({ message: "Unauthorized" });
        }

        const user = await userCollection.findOne({ email });

        if (!user || user.role !== "clubManager") {
          return res.status(403).send({
            message: "Forbidden: Club Manager access required",
          });
        }

        req.manager = user; // future use
        next();
      } catch (error) {
        res.status(500).send({ message: "Server error" });
      }
    };

    const verifyManagerOrAdmin = async (req, res, next) => {
      try {
        const email = req.user?.email;
        if (!email) {
          return res.status(401).send({ message: "Unauthorized" });
        }

        const user = await userCollection.findOne({ email });

        if (!user || (user.role !== "clubManager" && user.role !== "admin")) {
          return res.status(403).send({
            message: "Forbidden: Club Manager or Admin access required",
          });
        }

        req.userRole = user.role; // save role for later use
        next();
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
      }
    };

    app.get(
      "/manager/overview-stats",
      verifyToken,
      verifyClubManager,
      async (req, res) => {
        try {
          const managerEmail = req.user.email;

          // 1️⃣ Manager er clubs
          const clubs = await clubCollection.find({ managerEmail }).toArray();

          const clubIds = clubs.map((c) => c._id);

          // 2️⃣ Total members (memberships)
          const totalMembers = await membershipCollection.countDocuments({
            clubId: { $in: clubIds },
            status: "active",
          });

          // 3️⃣ Total events
          const totalEvents = await eventCollection.countDocuments({
            clubId: { $in: clubIds.map((id) => id.toString()) },
          });

          // 4️⃣ Total payments (paid only)
          const paymentResult = await paymentCollection
            .aggregate([
              {
                $match: {
                  clubId: { $in: clubIds },
                  status: "paid",
                },
              },
              {
                $group: {
                  _id: null,
                  totalAmount: { $sum: "$amount" },
                },
              },
            ])
            .toArray();

          const totalPayments = paymentResult[0]?.totalAmount || 0;

          res.send({
            clubsManaged: clubs.length,
            totalMembers,
            totalEvents,
            totalPayments,
          });
        } catch (error) {
          console.error(error);
          res.status(500).send({ message: "Failed to load manager stats" });
        }
      }
    );

    app.get("/admin/overview-stats", async (req, res) => {
      try {
        const totalUsers = await userCollection.countDocuments();
        const totalClubs = await clubCollection.countDocuments();
        const totalMembership = await membershipCollection.countDocuments();

        // ✅ Sum of all paid payments (membership + event)
        const paymentResult = await paymentCollection
          .aggregate([
            { $match: { status: "paid" } }, // free বাদ
            {
              $group: {
                _id: null,
                totalAmount: { $sum: "$amount" },
              },
            },
          ])
          .toArray();

        const totalPayments = paymentResult[0]?.totalAmount || 0;

        res.send({
          totalUsers,
          totalClubs,
          totalMembership,
          totalPayments,
        });
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Failed to fetch overview stats" });
      }
    });

    app.delete(
      "/clubs/:id",
      verifyToken,
      verifyManagerOrAdmin,
      async (req, res) => {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: "Invalid club ID format" });
        }

        const clubObjectId = new ObjectId(id);

        try {
          // ক্লাবটা আছে কিনা চেক করো
          const club = await clubCollection.findOne({ _id: clubObjectId });
          if (!club) {
            return res.status(404).json({ message: "Club not found" });
          }

          const requesterEmail = req.user.email;
          const requesterRole = req.userRole; // "admin" or "clubManager"

          // Permission logic:
          // - Admin: যেকোনো ক্লাব ডিলিট করতে পারবে
          // - Club Manager: শুধু নিজের ক্লাব (managerEmail match করলে)
          if (
            requesterRole !== "admin" &&
            club.managerEmail !== requesterEmail
          ) {
            return res.status(403).json({
              message: "Forbidden: You can only delete clubs you manage",
            });
          }

          // MongoDB Transaction দিয়ে সব related data ডিলিট করো
          const session = client.startSession();
          try {
            await session.withTransaction(async () => {
              // 1. ক্লাব ডিলিট
              await clubCollection.deleteOne(
                { _id: clubObjectId },
                { session }
              );

              // 2. Memberships ডিলিট
              await membershipCollection.deleteMany(
                { clubId: clubObjectId },
                { session }
              );

              // 3. Events ডিলিট (clubId string বা ObjectId দুইটাই match করার জন্য)
              await eventCollection.deleteMany(
                { clubId: { $in: [id, clubObjectId] } },
                { session }
              );

              // 4. Event Registrations ডিলিট
              await eventRegistrationCollection.deleteMany(
                { clubId: { $in: [id, clubObjectId] } },
                { session }
              );

              // 5. Payments ডিলিট
              await paymentCollection.deleteMany(
                { clubId: { $in: [id, clubObjectId] } },
                { session }
              );
            });

            res.json({
              success: true,
              message: "Club and all associated data deleted successfully",
            });
          } finally {
            await session.endSession();
          }
        } catch (error) {
          console.error("Club delete error:", error);
          res.status(500).json({
            message: "Failed to delete club. Please try again.",
          });
        }
      }
    );

    // GET /manager/club-members - Manager এর সব ক্লাবের মেম্বার ফেচ করা
    app.get(
      "/manager/club-members",
      verifyToken,
      verifyClubManager,
      async (req, res) => {
        try {
          const managerEmail = req.user.email;

          // 1. Manager এর সব ক্লাব খুঁজে নাও
          const myClubs = await clubCollection
            .find({ managerEmail })
            .project({ clubName: 1, _id: 1 })
            .toArray();

          if (myClubs.length === 0) {
            return res.send([]);
          }

          const clubIds = myClubs.map((club) => club._id);

          // 2. memberships collection থেকে এই ক্লাবগুলোর সব active member
          const memberships = await membershipCollection
            .aggregate([
              {
                $match: {
                  clubId: { $in: clubIds },
                  status: "active", // শুধু active মেম্বার
                },
              },
              {
                $lookup: {
                  from: "users",
                  localField: "userEmail",
                  foreignField: "email",
                  as: "userInfo",
                },
              },
              { $unwind: "$userInfo" },
              {
                $project: {
                  clubId: 1,
                  userEmail: 1,
                  name: "$userInfo.name",
                  photoURL: "$userInfo.photoURL",
                  status: 1,
                  joinedAt: 1,
                },
              },
            ])
            .toArray();

          // 3. ক্লাব অনুযায়ী গ্রুপ করো
          const result = myClubs.map((club) => ({
            clubId: club._id.toString(),
            clubName: club.clubName,
            members: memberships
              .filter((m) => m.clubId.toString() === club._id.toString())
              .map((m) => ({
                email: m.userEmail,
                name: m.name || "Unknown",
                photoURL: m.photoURL,
                status: m.status,
                joinedAt: m.joinedAt,
              })),
          }));

          res.send(result);
        } catch (error) {
          console.error("Error fetching club members:", error);
          res.status(500).send({ message: "Failed to fetch club members" });
        }
      }
    );

    // PATCH /manager/set-membership-expired
    app.patch(
      "/manager/set-membership-expired",
      verifyToken,
      verifyClubManager,
      async (req, res) => {
        const { clubId, userEmail } = req.body;

        if (!clubId || !userEmail) {
          return res
            .status(400)
            .send({ message: "clubId and userEmail required" });
        }

        try {
          const managerEmail = req.user.email;

          // চেক করো এই ক্লাবটা manager-এর কিনা
          const club = await clubCollection.findOne({
            _id: new ObjectId(clubId),
            managerEmail,
          });

          if (!club) {
            return res
              .status(403)
              .send({ message: "You can only manage your own clubs" });
          }

          // membership status expired করো
          const result = await membershipCollection.updateOne(
            {
              clubId: new ObjectId(clubId),
              userEmail: userEmail,
              status: "active",
            },
            { $set: { status: "expired", expiredAt: new Date() } }
          );

          if (result.modifiedCount === 0) {
            return res
              .status(404)
              .send({ message: "Membership not found or already expired" });
          }

          // club এর members array থেকে email remove (optional)
          await clubCollection.updateOne(
            { _id: new ObjectId(clubId) },
            { $pull: { members: userEmail } }
          );

          res.send({ success: true, message: "Membership set to expired" });
        } catch (error) {
          console.error("Error setting membership expired:", error);
          res.status(500).send({ message: "Server error" });
        }
      }
    );
    // ==============================
    // eventCollection collection api
    // ==============================
    // Get all events
    // Get all events for logged-in manager
    app.get(
      "/manager/events",
      verifyToken,
      verifyManagerOrAdmin,
      async (req, res) => {
        try {
          let events = [];

          if (req.userRole === "admin") {
            // Admin → সব events
            events = await eventCollection.find().toArray();
          } else {
            // Club Manager → নিজের events
            const managerEmail = req.user.email;

            const clubs = await clubCollection
              .find({ managerEmail })
              .project({ _id: 1 })
              .toArray();

            const clubIds = clubs.map((c) => c._id.toString());

            events = await eventCollection
              .find({
                clubId: { $in: clubIds },
              })
              .toArray();
          }

          res.send(events);
        } catch (error) {
          res.status(500).send({ message: "Failed to fetch events" });
        }
      }
    );

    app.get("/users/role-info", async (req, res) => {
      try {
        const { email } = req.query;

        if (!email) {
          return res.status(400).send({ message: "Email is required" });
        }

        // find user by email
        const user = await userCollection.findOne({ email });

        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        // response
        res.send({
          email: user.email,
          role: user.role,
        });
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
      }
    });

    app.get("/events", async (req, res) => {
      try {
        const events = await eventCollection.find().sort({ date: 1 }).toArray();
        res.send(events);
      } catch (err) {
        res.status(500).send({ message: "Error fetching events" });
      }
    });

    app.post("/events", async (req, res) => {
      try {
        const {
          title,
          description,
          date,
          location,
          isPaid,
          eventFee,
          maxAttendees,
          clubId,
          clubName,
        } = req.body;

        if (!clubId)
          return res.status(400).send({ message: "Club ID is required" });

        const newEvent = {
          title,
          description,
          date,
          location,
          isPaid,
          eventFee,
          maxAttendees,
          clubId, // save club id
          createdAt: new Date(),
          clubName,
        };

        const result = await eventCollection.insertOne(newEvent);
        res.status(201).send(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Failed to create event" });
      }
    });
    app.patch(
      "/events/:id",
      verifyToken,
      verifyManagerOrAdmin, // 🔥 admin + manager allowed
      async (req, res) => {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid event ID" });
        }

        const event = await eventCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!event) {
          return res.status(404).send({ message: "Event not found" });
        }

        // 🔐 Manager can update ONLY own club event
        if (
          req.userRole === "clubManager" &&
          event.clubId !== req.body.clubId &&
          event.clubId !== event.clubId
        ) {
          return res.status(403).send({ message: "Forbidden access" });
        }

        const result = await eventCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              ...req.body,
              updatedAt: new Date(),
            },
          }
        );

        res.send({ success: true, result });
      }
    );

    app.get("/events/:id", async (req, res) => {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: "Invalid event ID" });
      }

      const event = await eventCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!event) {
        return res.status(404).send({ message: "Event not found" });
      }

      res.send(event);
    });

    // DELETE /events/:id - Delete an event (Admin or Club Manager)
    app.delete(
      "/events/:id",
      verifyToken,
      verifyManagerOrAdmin,
      async (req, res) => {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: "Invalid event ID format" });
        }

        const eventObjectId = new ObjectId(id);

        try {
          // 1️⃣ Find the event
          const event = await eventCollection.findOne({ _id: eventObjectId });

          if (!event) {
            return res.status(404).json({ message: "Event not found" });
          }

          // 2️⃣ Permission check:
          // - Admin: can delete any event
          // - Club Manager: can delete only their own event
          if (req.userRole !== "admin") {
            const managerEmail = req.user.email;

            const club = await clubCollection.findOne({
              _id: new ObjectId(event.clubId),
            });

            if (!club || club.managerEmail !== managerEmail) {
              return res.status(403).json({
                message:
                  "Forbidden: You can only delete events of your own clubs",
              });
            }
          }

          // 3️⃣ Start a MongoDB session for transaction
          const session = client.startSession();
          try {
            await session.withTransaction(async () => {
              // a) Delete the event
              await eventCollection.deleteOne(
                { _id: eventObjectId },
                { session }
              );

              // b) Delete all payments related to this event
              await paymentCollection.deleteMany(
                { eventId: eventObjectId },
                { session }
              );

              // c) Delete all registrations for this event
              await eventRegistrationCollection.deleteMany(
                { eventId: eventObjectId },
                { session }
              );
            });

            res.json({
              success: true,
              message:
                "Event and all related payments & registrations deleted successfully",
            });
          } finally {
            await session.endSession();
          }
        } catch (error) {
          console.error("Event delete error:", error);
          res.status(500).json({ message: "Failed to delete event" });
        }
      }
    );

    // ==========================
    // payments method api
    // ==========================
    app.post("/create-payment-intent", verifyToken, async (req, res) => {
      try {
        const { amount } = req.body;

        if (!amount || amount <= 0) {
          return res.status(400).send({ message: "Invalid amount" });
        }

        const paymentIntent = await stripe.paymentIntents.create({
          amount: amount * 100,
          currency: "usd",
          payment_method_types: ["card"],
        });

        res.send({ clientSecret: paymentIntent.client_secret });
      } catch (error) {
        res.status(500).send({ message: error.message });
      }
    });

    app.post("/payments", verifyToken, async (req, res) => {
      try {
        const payment = {
          ...req.body,
          email: req.user.email,
          createdAt: new Date(),
        };

        const result = await paymentCollection.insertOne(payment);

        // // optional: add membership
        // await membershipCollection.insertOne({
        //   clubId: new ObjectId(payment.clubId),
        //   email: req.user.email,
        //   status: "active",
        //   joinedAt: new Date(),
        // });

        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Payment save failed" });
      }
    });

    app.get("/admin/payments", verifyToken, verifyAdmin, async (req, res) => {
      const payments = await paymentCollection
        .find()
        .sort({ createdAt: -1 })
        .toArray();
      res.send(payments);
    });

    app.post("/join-club", verifyToken, async (req, res) => {
      try {
        const { clubId, paymentId = null, amount = 0 } = req.body;
        const email = req.user.email;

        if (!clubId) {
          return res.status(400).send({ message: "Club ID is required" });
        }

        // Already member check
        const alreadyMember = await membershipCollection.findOne({
          clubId: new ObjectId(clubId),
          userEmail: email,
          status: "active",
        });

        if (alreadyMember) {
          return res
            .status(400)
            .send({ message: "You are already a member of this club" });
        }

        // 1. Save to payments collection (full schema)
        const paymentDoc = {
          userEmail: email,
          amount: Number(amount),
          type: "membership", // fixed for club join
          clubId: new ObjectId(clubId),
          eventId: null, // membership হলে null
          stripePaymentIntentId: paymentId || null,
          status: paymentId ? "paid" : "free",
          createdAt: new Date(),
        };

        await paymentCollection.insertOne(paymentDoc);

        // 2. Save to memberships collection
        const membershipDoc = {
          userEmail: email,
          clubId: new ObjectId(clubId),
          status: "active",
          paymentId: paymentId || null,
          joinedAt: new Date(),
        };

        await membershipCollection.insertOne(membershipDoc);

        // 3. Update club's members array (members count-এর জন্য)
        await clubCollection.updateOne(
          { _id: new ObjectId(clubId) },
          {
            $addToSet: { members: email },
            $set: { updatedAt: new Date() },
          }
        );

        res.send({
          success: true,
          message: "Successfully joined the club!",
        });
      } catch (error) {
        console.error("Join club error:", error);
        res.status(500).send({ message: "Failed to join club" });
      }
    });

    // ===============================
    // eventRegistrationCollection api
    // ===============================
    // Register for an event (free or paid)
    app.post("/register-event", verifyToken, async (req, res) => {
      try {
        const { eventId, paymentId = null, amount = 0 } = req.body;
        const email = req.user.email;

        if (!eventId) {
          return res.status(400).send({ message: "Event ID is required" });
        }

        // Check if event exists
        const event = await eventCollection.findOne({
          _id: new ObjectId(eventId),
        });
        if (!event) {
          return res.status(404).send({ message: "Event not found" });
        }

        // Check if already registered
        const alreadyRegistered = await eventRegistrationCollection.findOne({
          eventId: new ObjectId(eventId),
          userEmail: email,
          status: { $in: ["registered", "cancelled"] },
        });

        if (alreadyRegistered) {
          return res
            .status(400)
            .send({ message: "You are already registered for this event" });
        }

        // 1. Save to payments collection (if paid or free)
        const paymentDoc = {
          userEmail: email,
          amount: Number(amount),
          type: "event",
          clubId: new ObjectId(event.clubId),
          eventId: new ObjectId(eventId),
          stripePaymentIntentId: paymentId || null,
          status: paymentId ? "paid" : "free",
          createdAt: new Date(),
        };

        await paymentCollection.insertOne(paymentDoc);

        // 2. Save to eventRegistrations collection
        const registrationDoc = {
          eventId: new ObjectId(eventId),
          userEmail: email,
          clubId: new ObjectId(event.clubId),
          status: "registered",
          paymentId: paymentId || null,
          registeredAt: new Date(),
        };

        await eventRegistrationCollection.insertOne(registrationDoc);

        res.send({
          success: true,
          message: "Successfully registered for the event!",
        });
      } catch (error) {
        console.error("Event registration error:", error);
        res.status(500).send({ message: "Failed to register for event" });
      }
    });

    // GET /my-event-registrations
    app.get("/my-event-registrations", verifyToken, async (req, res) => {
      try {
        const email = req.user.email;

        const registrations = await eventRegistrationCollection
          .aggregate([
            {
              $match: { userEmail: email },
            },
            {
              $lookup: {
                from: "events",
                localField: "eventId",
                foreignField: "_id",
                as: "eventInfo",
              },
            },
            { $unwind: "$eventInfo" },
            {
              $project: {
                _id: 1,
                status: 1,
                registeredAt: 1,
                "eventInfo.title": 1,
                "eventInfo.date": 1,
                "eventInfo.location": 1,
                "eventInfo.clubName": 1,
              },
            },
          ])
          .toArray();

        res.send(registrations);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Failed to fetch registrations" });
      }
    });

    // ===============================
    // Member Overview API
    // ===============================
    app.get("/member-overview", verifyToken, async (req, res) => {
      try {
        const email = req.user.email;
        console.log("🔍 Member overview requested for:", email); // Terminal log

        // 1️⃣ Total Active Clubs
        const totalClubs = await membershipCollection.countDocuments({
          userEmail: email,
          status: "active",
        });
        console.log("📊 Total clubs:", totalClubs);

        // 2️⃣ Total Registered Events
        const totalEvents = await eventRegistrationCollection.countDocuments({
          userEmail: email,
          status: "registered",
        });
        console.log("📊 Total events:", totalEvents);

        // 3️⃣ Upcoming Events
        const memberships = await membershipCollection
          .find({ userEmail: email, status: "active" })
          .toArray();

        const clubIds = memberships
          .map((m) => m.clubId?.toString())
          .filter(Boolean);

        let upcomingEvents = [];
        if (clubIds.length > 0) {
          upcomingEvents = await eventCollection
            .aggregate([
              {
                $match: {
                  clubId: { $in: clubIds.map((id) => new ObjectId(id)) },
                  date: { $gte: new Date() },
                },
              },
              { $sort: { date: 1 } },
              {
                $lookup: {
                  from: "clubs",
                  localField: "clubId",
                  foreignField: "_id",
                  as: "clubInfo",
                },
              },
              {
                $unwind: {
                  path: "$clubInfo",
                  preserveNullAndEmptyArrays: true,
                },
              },
              {
                $project: {
                  _id: 1,
                  title: 1,
                  date: 1,
                  location: 1,
                  clubName: { $ifNull: ["$clubInfo.clubName", "Unknown Club"] },
                },
              },
              { $limit: 5 },
            ])
            .toArray();
        }

        console.log("🎉 Upcoming events found:", upcomingEvents.length);

        res.send({ totalClubs, totalEvents, upcomingEvents });
      } catch (error) {
        console.error("💥 Member Overview ERROR:", error);
        res.status(500).send({ message: "Failed to fetch member overview" });
      }
    });

    app.get("/dashboard/member/my-clubs", verifyToken, async (req, res) => {
      try {
        const email = req.user.email;

        const memberships = await membershipCollection
          .find({
            userEmail: email,
            status: "active",
          })
          .toArray();

        const clubIds = memberships.map((m) => m.clubId);

        const clubs = await clubCollection
          .find({
            _id: { $in: clubIds },
          })
          .toArray();

        // Combine membership info (expiry date, status)
        const result = clubs.map((club) => {
          const membership = memberships.find(
            (m) => m.clubId.toString() === club._id.toString()
          );
          return {
            clubName: club.clubName,
            location: club.location,
            status: membership.status,
            expiryDate: membership.expiredAt || null,
            clubId: club._id,
          };
        });

        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Failed to fetch my clubs" });
      }
    });

    app.get("/dashboard/member/my-events", verifyToken, async (req, res) => {
      try {
        const email = req.user.email;

        const registrations = await eventRegistrationCollection
          .aggregate([
            { $match: { userEmail: email } },
            {
              $lookup: {
                from: "events",
                localField: "eventId",
                foreignField: "_id",
                as: "eventInfo",
              },
            },
            { $unwind: "$eventInfo" },
            {
              $project: {
                _id: 1,
                status: 1,
                registeredAt: 1,
                "eventInfo.title": 1,
                "eventInfo.date": 1,
                "eventInfo.clubName": 1,
              },
            },
          ])
          .toArray();

        res.send(registrations);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Failed to fetch my events" });
      }
    });

    // const { ObjectId } = require("mongodb");

    app.get("/dashboard/member/payments", verifyToken, async (req, res) => {
      try {
        const email = req.user.email;

        const payments = await paymentCollection
          .aggregate([
            // 1️⃣ Logged-in user payments
            { $match: { userEmail: email } },

            // 2️⃣ Club lookup (membership payment)
            {
              $lookup: {
                from: "clubs",
                localField: "clubId",
                foreignField: "_id",
                as: "clubInfo",
              },
            },

            // 3️⃣ Event lookup (event payment)
            {
              $lookup: {
                from: "events",
                localField: "eventId",
                foreignField: "_id",
                as: "eventInfo",
              },
            },

            // 4️⃣ Clean response
            {
              $project: {
                amount: 1,
                type: 1,
                status: 1,
                createdAt: 1,

                // membership → club name
                clubName: {
                  $cond: [
                    { $eq: ["$type", "membership"] },
                    { $arrayElemAt: ["$clubInfo.clubName", 0] },
                    null,
                  ],
                },

                // event → event title
                eventTitle: {
                  $cond: [
                    { $eq: ["$type", "event"] },
                    { $arrayElemAt: ["$eventInfo.title", 0] },
                    null,
                  ],
                },
              },
            },

            // 5️⃣ Latest first
            { $sort: { createdAt: -1 } },
          ])
          .toArray();

        res.send(payments);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Failed to fetch payments" });
      }
    });


   
app.get("/admin/chart-data", verifyToken, verifyAdmin, async (req, res) => {
  try {
    
    const chartData = await membershipCollection.aggregate([
      {
        $group: {
          _id: "$clubId",
          memberCount: { $sum: 1 }
        }
      },
      {
        $lookup: {
          from: "clubs",
          localField: "_id",
          foreignField: "_id",
          as: "clubDetails"
        }
      },
      { $unwind: "$clubDetails" },
      {
        $project: {
          name: "$clubDetails.clubName",
          value: "$memberCount",
          _id: 0
        }
      }
    ]).toArray();

    res.send(chartData);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch chart data" });
  }
});

    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // await client.close();
  }
}
run().catch(console.dir);

app.listen(port, () => {
  console.log(`simple crud server is running on port ${port}`);
});
